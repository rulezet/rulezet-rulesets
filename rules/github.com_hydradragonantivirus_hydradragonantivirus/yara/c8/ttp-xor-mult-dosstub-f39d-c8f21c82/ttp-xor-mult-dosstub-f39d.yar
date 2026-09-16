rule TTP_XOR_MULT_DOSStub_f39d {
  strings:
    $key_f39d = { a7 f5 [2] d3 ed [2] 94 ef [2] d3 fe [2] 9d f2 [2] 91 f8 [2] 86 f3 [2] 9d bd [2] a0 }

  condition:
    any of them
}