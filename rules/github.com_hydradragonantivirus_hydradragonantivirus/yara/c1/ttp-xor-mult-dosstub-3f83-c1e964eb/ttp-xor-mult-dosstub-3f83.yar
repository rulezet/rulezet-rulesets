rule TTP_XOR_MULT_DOSStub_3f83 {
  strings:
    $key_3f83 = { 6b eb [2] 1f f3 [2] 58 f1 [2] 1f e0 [2] 51 ec [2] 5d e6 [2] 4a ed [2] 51 a3 [2] 6c }

  condition:
    any of them
}