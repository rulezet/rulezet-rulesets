rule TTP_XOR_QUAD_CurrentVersionRun_0c77 {
  strings:
    $key_0c77 = { 5f 18 [2] 7b 16 [2] 50 3a [2] 7e 18 [2] 6a 03 [2] 65 19 [2] 7b 04 [2] 79 05 [2] 62 03 [2] 7e 04 [2] 62 2b }

  condition:
    any of them
}