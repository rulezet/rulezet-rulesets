rule TTP_XOR_QUAD_CurrentVersionRun_5776 {
  strings:
    $key_5776 = { 04 19 [2] 20 17 [2] 0b 3b [2] 25 19 [2] 31 02 [2] 3e 18 [2] 20 05 [2] 22 04 [2] 39 02 [2] 25 05 [2] 39 2a }

  condition:
    any of them
}