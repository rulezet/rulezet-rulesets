rule TTP_XOR_MULT_DOSStub_439d {
  strings:
    $key_439d = { 17 f5 [2] 63 ed [2] 24 ef [2] 63 fe [2] 2d f2 [2] 21 f8 [2] 36 f3 [2] 2d bd [2] 10 }

  condition:
    any of them
}