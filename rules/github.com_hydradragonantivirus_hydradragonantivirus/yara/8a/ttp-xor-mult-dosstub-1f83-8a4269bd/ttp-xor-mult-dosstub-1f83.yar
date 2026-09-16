rule TTP_XOR_MULT_DOSStub_1f83 {
  strings:
    $key_1f83 = { 4b eb [2] 3f f3 [2] 78 f1 [2] 3f e0 [2] 71 ec [2] 7d e6 [2] 6a ed [2] 71 a3 [2] 4c }

  condition:
    any of them
}