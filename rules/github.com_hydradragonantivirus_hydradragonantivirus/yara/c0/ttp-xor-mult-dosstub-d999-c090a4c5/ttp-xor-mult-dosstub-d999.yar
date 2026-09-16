rule TTP_XOR_MULT_DOSStub_d999 {
  strings:
    $key_d999 = { 8d f1 [2] f9 e9 [2] be eb [2] f9 fa [2] b7 f6 [2] bb fc [2] ac f7 [2] b7 b9 [2] 8a }

  condition:
    any of them
}