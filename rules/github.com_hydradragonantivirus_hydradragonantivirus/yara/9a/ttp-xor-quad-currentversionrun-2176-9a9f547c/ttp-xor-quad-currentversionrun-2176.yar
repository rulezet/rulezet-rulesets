rule TTP_XOR_QUAD_CurrentVersionRun_2176 {
  strings:
    $key_2176 = { 72 19 [2] 56 17 [2] 7d 3b [2] 53 19 [2] 47 02 [2] 48 18 [2] 56 05 [2] 54 04 [2] 4f 02 [2] 53 05 [2] 4f 2a }

  condition:
    any of them
}