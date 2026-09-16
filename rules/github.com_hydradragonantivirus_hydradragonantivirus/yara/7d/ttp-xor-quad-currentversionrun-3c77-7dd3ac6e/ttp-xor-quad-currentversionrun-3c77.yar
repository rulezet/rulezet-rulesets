rule TTP_XOR_QUAD_CurrentVersionRun_3c77 {
  strings:
    $key_3c77 = { 6f 18 [2] 4b 16 [2] 60 3a [2] 4e 18 [2] 5a 03 [2] 55 19 [2] 4b 04 [2] 49 05 [2] 52 03 [2] 4e 04 [2] 52 2b }

  condition:
    any of them
}