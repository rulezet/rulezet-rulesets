rule TTP_XOR_MULT_DOSStub_f09b {
  strings:
    $key_f09b = { a4 f3 [2] d0 eb [2] 97 e9 [2] d0 f8 [2] 9e f4 [2] 92 fe [2] 85 f5 [2] 9e bb [2] a3 }

  condition:
    any of them
}