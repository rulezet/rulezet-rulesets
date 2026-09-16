rule TTP_XOR_MULT_DOSStub_ecf2 {
  strings:
    $key_ecf2 = { b8 9a [2] cc 82 [2] 8b 80 [2] cc 91 [2] 82 9d [2] 8e 97 [2] 99 9c [2] 82 d2 [2] bf }

  condition:
    any of them
}