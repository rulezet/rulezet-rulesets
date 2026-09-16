rule TTP_XOR_MULT_DOSStub_b999 {
  strings:
    $key_b999 = { ed f1 [2] 99 e9 [2] de eb [2] 99 fa [2] d7 f6 [2] db fc [2] cc f7 [2] d7 b9 [2] ea }

  condition:
    any of them
}