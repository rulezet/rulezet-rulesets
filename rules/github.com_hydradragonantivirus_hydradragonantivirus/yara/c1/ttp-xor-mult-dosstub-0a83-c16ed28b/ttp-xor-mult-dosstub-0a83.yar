rule TTP_XOR_MULT_DOSStub_0a83 {
  strings:
    $key_0a83 = { 5e eb [2] 2a f3 [2] 6d f1 [2] 2a e0 [2] 64 ec [2] 68 e6 [2] 7f ed [2] 64 a3 [2] 59 }

  condition:
    any of them
}