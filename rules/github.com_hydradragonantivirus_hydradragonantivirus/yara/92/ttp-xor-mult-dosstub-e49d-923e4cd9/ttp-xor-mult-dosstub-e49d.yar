rule TTP_XOR_MULT_DOSStub_e49d {
  strings:
    $key_e49d = { b0 f5 [2] c4 ed [2] 83 ef [2] c4 fe [2] 8a f2 [2] 86 f8 [2] 91 f3 [2] 8a bd [2] b7 }

  condition:
    any of them
}