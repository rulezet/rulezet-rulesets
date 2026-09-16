rule TTP_XOR_MULT_DOSStub_f09f {
  strings:
    $key_f09f = { a4 f7 [2] d0 ef [2] 97 ed [2] d0 fc [2] 9e f0 [2] 92 fa [2] 85 f1 [2] 9e bf [2] a3 }

  condition:
    any of them
}