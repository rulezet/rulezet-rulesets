rule TTP_XOR_MULT_DOSStub_ece0 {
  strings:
    $key_ece0 = { b8 88 [2] cc 90 [2] 8b 92 [2] cc 83 [2] 82 8f [2] 8e 85 [2] 99 8e [2] 82 c0 [2] bf }

  condition:
    any of them
}