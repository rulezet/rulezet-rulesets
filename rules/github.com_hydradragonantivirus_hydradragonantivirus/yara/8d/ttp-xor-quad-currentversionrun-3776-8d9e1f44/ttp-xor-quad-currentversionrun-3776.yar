rule TTP_XOR_QUAD_CurrentVersionRun_3776 {
  strings:
    $key_3776 = { 64 19 [2] 40 17 [2] 6b 3b [2] 45 19 [2] 51 02 [2] 5e 18 [2] 40 05 [2] 42 04 [2] 59 02 [2] 45 05 [2] 59 2a }

  condition:
    any of them
}