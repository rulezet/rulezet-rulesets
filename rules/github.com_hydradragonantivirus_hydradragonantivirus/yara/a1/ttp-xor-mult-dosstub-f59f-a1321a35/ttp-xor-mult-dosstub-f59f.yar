rule TTP_XOR_MULT_DOSStub_f59f {
  strings:
    $key_f59f = { a1 f7 [2] d5 ef [2] 92 ed [2] d5 fc [2] 9b f0 [2] 97 fa [2] 80 f1 [2] 9b bf [2] a6 }

  condition:
    any of them
}