rule TTP_XOR_MULT_DOSStub_e818 {
  strings:
    $key_e818 = { bc 70 [2] c8 68 [2] 8f 6a [2] c8 7b [2] 86 77 [2] 8a 7d [2] 9d 76 [2] 86 38 [2] bb }

  condition:
    any of them
}