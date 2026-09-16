rule TTP_XOR_MULT_DOSStub_e8f9 {
  strings:
    $key_e8f9 = { bc 91 [2] c8 89 [2] 8f 8b [2] c8 9a [2] 86 96 [2] 8a 9c [2] 9d 97 [2] 86 d9 [2] bb }

  condition:
    any of them
}