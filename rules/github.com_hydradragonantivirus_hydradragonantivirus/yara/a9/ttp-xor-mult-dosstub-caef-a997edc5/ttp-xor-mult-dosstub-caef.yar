rule TTP_XOR_MULT_DOSStub_caef {
  strings:
    $key_caef = { 9e 87 [2] ea 9f [2] ad 9d [2] ea 8c [2] a4 80 [2] a8 8a [2] bf 81 [2] a4 cf [2] 99 }

  condition:
    any of them
}