rule TTP_XOR_QUAD_CurrentVersionRun_7763 {
  strings:
    $key_7763 = { 24 0c [2] 00 02 [2] 2b 2e [2] 05 0c [2] 11 17 [2] 1e 0d [2] 00 10 [2] 02 11 [2] 19 17 [2] 05 10 [2] 19 3f }

  condition:
    any of them
}