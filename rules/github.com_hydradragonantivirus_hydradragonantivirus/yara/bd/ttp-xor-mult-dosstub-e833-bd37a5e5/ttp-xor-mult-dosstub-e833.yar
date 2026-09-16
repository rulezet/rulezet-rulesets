rule TTP_XOR_MULT_DOSStub_e833 {
  strings:
    $key_e833 = { bc 5b [2] c8 43 [2] 8f 41 [2] c8 50 [2] 86 5c [2] 8a 56 [2] 9d 5d [2] 86 13 [2] bb }

  condition:
    any of them
}