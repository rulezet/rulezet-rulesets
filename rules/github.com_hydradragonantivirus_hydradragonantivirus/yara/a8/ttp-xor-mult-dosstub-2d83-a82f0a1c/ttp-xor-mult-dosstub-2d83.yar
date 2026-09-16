rule TTP_XOR_MULT_DOSStub_2d83 {
  strings:
    $key_2d83 = { 79 eb [2] 0d f3 [2] 4a f1 [2] 0d e0 [2] 43 ec [2] 4f e6 [2] 58 ed [2] 43 a3 [2] 7e }

  condition:
    any of them
}