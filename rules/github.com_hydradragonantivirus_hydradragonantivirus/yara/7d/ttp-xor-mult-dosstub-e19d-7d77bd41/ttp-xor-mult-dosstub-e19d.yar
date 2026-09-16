rule TTP_XOR_MULT_DOSStub_e19d {
  strings:
    $key_e19d = { b5 f5 [2] c1 ed [2] 86 ef [2] c1 fe [2] 8f f2 [2] 83 f8 [2] 94 f3 [2] 8f bd [2] b2 }

  condition:
    any of them
}