rule TTP_XOR_MULT_DOSStub_2a83 {
  strings:
    $key_2a83 = { 7e eb [2] 0a f3 [2] 4d f1 [2] 0a e0 [2] 44 ec [2] 48 e6 [2] 5f ed [2] 44 a3 [2] 79 }

  condition:
    any of them
}