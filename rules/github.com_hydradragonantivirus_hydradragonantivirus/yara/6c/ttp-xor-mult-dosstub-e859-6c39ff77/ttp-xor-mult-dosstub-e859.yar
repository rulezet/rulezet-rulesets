rule TTP_XOR_MULT_DOSStub_e859 {
  strings:
    $key_e859 = { bc 31 [2] c8 29 [2] 8f 2b [2] c8 3a [2] 86 36 [2] 8a 3c [2] 9d 37 [2] 86 79 [2] bb }

  condition:
    any of them
}