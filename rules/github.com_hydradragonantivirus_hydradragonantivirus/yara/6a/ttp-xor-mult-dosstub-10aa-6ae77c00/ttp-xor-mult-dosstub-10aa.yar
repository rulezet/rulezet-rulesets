rule TTP_XOR_MULT_DOSStub_10aa {
  strings:
    $key_10aa = { 44 c2 [2] 30 da [2] 77 d8 [2] 30 c9 [2] 7e c5 [2] 72 cf [2] 65 c4 [2] 7e 8a [2] 43 }

  condition:
    any of them
}