rule TTP_XOR_MULT_DOSStub_e813 {
  strings:
    $key_e813 = { bc 7b [2] c8 63 [2] 8f 61 [2] c8 70 [2] 86 7c [2] 8a 76 [2] 9d 7d [2] 86 33 [2] bb }

  condition:
    any of them
}