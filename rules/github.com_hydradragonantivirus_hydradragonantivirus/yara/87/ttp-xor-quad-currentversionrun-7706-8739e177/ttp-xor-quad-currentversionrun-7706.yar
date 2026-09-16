rule TTP_XOR_QUAD_CurrentVersionRun_7706 {
  strings:
    $key_7706 = { 24 69 [2] 00 67 [2] 2b 4b [2] 05 69 [2] 11 72 [2] 1e 68 [2] 00 75 [2] 02 74 [2] 19 72 [2] 05 75 [2] 19 5a }

  condition:
    any of them
}