rule TTP_XOR_MULT_DOSStub_e805 {
  strings:
    $key_e805 = { bc 6d [2] c8 75 [2] 8f 77 [2] c8 66 [2] 86 6a [2] 8a 60 [2] 9d 6b [2] 86 25 [2] bb }

  condition:
    any of them
}