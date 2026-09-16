rule TTP_XOR_MULT_DOSStub_e39d {
  strings:
    $key_e39d = { b7 f5 [2] c3 ed [2] 84 ef [2] c3 fe [2] 8d f2 [2] 81 f8 [2] 96 f3 [2] 8d bd [2] b0 }

  condition:
    any of them
}