rule TTP_XOR_QUAD_CurrentVersionRun_7726 {
  strings:
    $key_7726 = { 24 49 [2] 00 47 [2] 2b 6b [2] 05 49 [2] 11 52 [2] 1e 48 [2] 00 55 [2] 02 54 [2] 19 52 [2] 05 55 [2] 19 7a }

  condition:
    any of them
}