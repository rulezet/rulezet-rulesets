rule TTP_XOR_MULT_DOSStub_019d {
  strings:
    $key_019d = { 55 f5 [2] 21 ed [2] 66 ef [2] 21 fe [2] 6f f2 [2] 63 f8 [2] 74 f3 [2] 6f bd [2] 52 }

  condition:
    any of them
}