rule TTP_XOR_MULT_DOSStub_5069 {
  strings:
    $key_5069 = { 04 01 [2] 70 19 [2] 37 1b [2] 70 0a [2] 3e 06 [2] 32 0c [2] 25 07 [2] 3e 49 [2] 03 }

  condition:
    any of them
}