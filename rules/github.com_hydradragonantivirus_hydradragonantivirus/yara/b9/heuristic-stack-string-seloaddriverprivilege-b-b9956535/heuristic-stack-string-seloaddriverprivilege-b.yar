rule Heuristic_Stack_String_SeLoadDriverPrivilege_B {
  meta:
    description = "Detects the stack string SeLoadDriverPrivilege being loaded in a combination of 1, 2, and 4 byte chunks, not necessarily in order"
    author      = "BitsOfBinary"
    reference   = "https://bitsofbinary.github.io/yara/2023/04/07/100daysofyara-day-97.html"
    version     = "1.0"
    date        = "2023-04-07"
    DaysofYARA  = "97/100"

  strings:
    $one_byte_mov_S_stack     = { C6 44 24 ?? 53 }
    $one_byte_mov_e_stack     = { C6 44 24 ?? 65 }
    $one_byte_mov_L_stack     = { C6 44 24 ?? 4c }
    $one_byte_mov_o_stack     = { C6 44 24 ?? 6f }
    $one_byte_mov_a_stack     = { C6 44 24 ?? 61 }
    $one_byte_mov_d_stack     = { C6 44 24 ?? 64 }
    $one_byte_mov_D_stack     = { C6 44 24 ?? 44 }
    $one_byte_mov_r_stack     = { C6 44 24 ?? 72 }
    $one_byte_mov_i_stack     = { C6 44 24 ?? 69 }
    $one_byte_mov_v_stack     = { C6 44 24 ?? 76 }
    $one_byte_mov_P_stack     = { C6 44 24 ?? 50 }
    $one_byte_mov_l_stack     = { C6 44 24 ?? 6c }
    $one_byte_mov_g_stack     = { C6 44 24 ?? 67 }
    $two_byte_mov_Se_stack    = { 66 C7 44 24 ?? 53 65 }
    $two_byte_mov_eL_stack    = { 66 C7 44 24 ?? 65 4c }
    $two_byte_mov_Lo_stack    = { 66 C7 44 24 ?? 4c 6f }
    $two_byte_mov_oa_stack    = { 66 C7 44 24 ?? 6f 61 }
    $two_byte_mov_ad_stack    = { 66 C7 44 24 ?? 61 64 }
    $two_byte_mov_dD_stack    = { 66 C7 44 24 ?? 64 44 }
    $two_byte_mov_Dr_stack    = { 66 C7 44 24 ?? 44 72 }
    $two_byte_mov_ri_stack    = { 66 C7 44 24 ?? 72 69 }
    $two_byte_mov_iv_stack    = { 66 C7 44 24 ?? 69 76 }
    $two_byte_mov_ve_stack    = { 66 C7 44 24 ?? 76 65 }
    $two_byte_mov_er_stack    = { 66 C7 44 24 ?? 65 72 }
    $two_byte_mov_rP_stack    = { 66 C7 44 24 ?? 72 50 }
    $two_byte_mov_Pr_stack    = { 66 C7 44 24 ?? 50 72 }
    $two_byte_mov_vi_stack    = { 66 C7 44 24 ?? 76 69 }
    $two_byte_mov_il_stack    = { 66 C7 44 24 ?? 69 6c }
    $two_byte_mov_le_stack    = { 66 C7 44 24 ?? 6c 65 }
    $two_byte_mov_eg_stack    = { 66 C7 44 24 ?? 65 67 }
    $two_byte_mov_ge_stack    = { 66 C7 44 24 ?? 67 65 }
    $four_byte_mov_SeLo_stack = { C7 44 24 ?? 53 65 4c 6f }
    $four_byte_mov_eLoa_stack = { C7 44 24 ?? 65 4c 6f 61 }
    $four_byte_mov_Load_stack = { C7 44 24 ?? 4c 6f 61 64 }
    $four_byte_mov_oadD_stack = { C7 44 24 ?? 6f 61 64 44 }
    $four_byte_mov_adDr_stack = { C7 44 24 ?? 61 64 44 72 }
    $four_byte_mov_dDri_stack = { C7 44 24 ?? 64 44 72 69 }
    $four_byte_mov_Driv_stack = { C7 44 24 ?? 44 72 69 76 }
    $four_byte_mov_rive_stack = { C7 44 24 ?? 72 69 76 65 }
    $four_byte_mov_iver_stack = { C7 44 24 ?? 69 76 65 72 }
    $four_byte_mov_verP_stack = { C7 44 24 ?? 76 65 72 50 }
    $four_byte_mov_erPr_stack = { C7 44 24 ?? 65 72 50 72 }
    $four_byte_mov_rPri_stack = { C7 44 24 ?? 72 50 72 69 }
    $four_byte_mov_Priv_stack = { C7 44 24 ?? 50 72 69 76 }
    $four_byte_mov_rivi_stack = { C7 44 24 ?? 72 69 76 69 }
    $four_byte_mov_ivil_stack = { C7 44 24 ?? 69 76 69 6c }
    $four_byte_mov_vile_stack = { C7 44 24 ?? 76 69 6c 65 }
    $four_byte_mov_ileg_stack = { C7 44 24 ?? 69 6c 65 67 }
    $four_byte_mov_lege_stack = { C7 44 24 ?? 6c 65 67 65 }

  condition:
    for any of them: (
      any of ($one_byte*) in (@ - 100..@ + 100) and
      any of ($two_byte*) in (@ - 100..@ + 100) and
      any of ($four_byte*) in (@ - 100..@ + 100)
    )
}