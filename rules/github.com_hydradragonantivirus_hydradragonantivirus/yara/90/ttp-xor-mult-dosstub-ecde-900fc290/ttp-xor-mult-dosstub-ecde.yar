rule TTP_XOR_MULT_DOSStub_ecde {
  strings:
    $key_ecde = { b8 b6 [2] cc ae [2] 8b ac [2] cc bd [2] 82 b1 [2] 8e bb [2] 99 b0 [2] 82 fe [2] bf }

  condition:
    any of them
}