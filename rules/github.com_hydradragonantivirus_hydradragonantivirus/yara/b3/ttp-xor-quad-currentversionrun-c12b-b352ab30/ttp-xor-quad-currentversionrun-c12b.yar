rule TTP_XOR_QUAD_CurrentVersionRun_c12b {
  strings:
    $key_c12b = { 92 44 [2] b6 4a [2] 9d 66 [2] b3 44 [2] a7 5f [2] a8 45 [2] b6 58 [2] b4 59 [2] af 5f [2] b3 58 [2] af 77 }

  condition:
    any of them
}