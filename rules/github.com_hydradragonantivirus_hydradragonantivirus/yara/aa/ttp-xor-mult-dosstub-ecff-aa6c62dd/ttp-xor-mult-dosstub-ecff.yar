rule TTP_XOR_MULT_DOSStub_ecff {
  strings:
    $key_ecff = { b8 97 [2] cc 8f [2] 8b 8d [2] cc 9c [2] 82 90 [2] 8e 9a [2] 99 91 [2] 82 df [2] bf }

  condition:
    any of them
}