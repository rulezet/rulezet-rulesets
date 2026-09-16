rule TTP_XOR_MULT_DOSStub_b164 {
  strings:
    $key_b164 = { e5 0c [2] 91 14 [2] d6 16 [2] 91 07 [2] df 0b [2] d3 01 [2] c4 0a [2] df 44 [2] e2 }

  condition:
    any of them
}