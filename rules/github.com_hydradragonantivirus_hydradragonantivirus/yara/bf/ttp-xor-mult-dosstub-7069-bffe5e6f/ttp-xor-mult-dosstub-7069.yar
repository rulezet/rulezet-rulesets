rule TTP_XOR_MULT_DOSStub_7069 {
  strings:
    $key_7069 = { 24 01 [2] 50 19 [2] 17 1b [2] 50 0a [2] 1e 06 [2] 12 0c [2] 05 07 [2] 1e 49 [2] 23 }

  condition:
    any of them
}