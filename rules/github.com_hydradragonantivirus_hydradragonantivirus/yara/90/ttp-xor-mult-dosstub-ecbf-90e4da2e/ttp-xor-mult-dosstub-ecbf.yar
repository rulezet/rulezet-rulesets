rule TTP_XOR_MULT_DOSStub_ecbf {
  strings:
    $key_ecbf = { b8 d7 [2] cc cf [2] 8b cd [2] cc dc [2] 82 d0 [2] 8e da [2] 99 d1 [2] 82 9f [2] bf }

  condition:
    any of them
}