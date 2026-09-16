rule TTP_XOR_MULT_DOSStub_8aaa {
  strings:
    $key_8aaa = { de c2 [2] aa da [2] ed d8 [2] aa c9 [2] e4 c5 [2] e8 cf [2] ff c4 [2] e4 8a [2] d9 }

  condition:
    any of them
}