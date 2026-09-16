rule TTP_XOR_QUAD_CurrentVersionRun_762b {
  strings:
    $key_762b = { 25 44 [2] 01 4a [2] 2a 66 [2] 04 44 [2] 10 5f [2] 1f 45 [2] 01 58 [2] 03 59 [2] 18 5f [2] 04 58 [2] 18 77 }

  condition:
    any of them
}