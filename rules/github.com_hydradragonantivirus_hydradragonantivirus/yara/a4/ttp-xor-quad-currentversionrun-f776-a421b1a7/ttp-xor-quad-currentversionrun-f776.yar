rule TTP_XOR_QUAD_CurrentVersionRun_f776 {
  strings:
    $key_f776 = { a4 19 [2] 80 17 [2] ab 3b [2] 85 19 [2] 91 02 [2] 9e 18 [2] 80 05 [2] 82 04 [2] 99 02 [2] 85 05 [2] 99 2a }

  condition:
    any of them
}