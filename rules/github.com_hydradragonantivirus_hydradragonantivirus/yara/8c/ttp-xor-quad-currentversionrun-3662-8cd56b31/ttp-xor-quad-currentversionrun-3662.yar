rule TTP_XOR_QUAD_CurrentVersionRun_3662 {
  strings:
    $key_3662 = { 65 0d [2] 41 03 [2] 6a 2f [2] 44 0d [2] 50 16 [2] 5f 0c [2] 41 11 [2] 43 10 [2] 58 16 [2] 44 11 [2] 58 3e }

  condition:
    any of them
}