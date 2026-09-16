rule TTP_XOR_QUAD_CurrentVersionRun_3022 {
  strings:
    $key_3022 = { 63 4d [2] 47 43 [2] 6c 6f [2] 42 4d [2] 56 56 [2] 59 4c [2] 47 51 [2] 45 50 [2] 5e 56 [2] 42 51 [2] 5e 7e }

  condition:
    any of them
}