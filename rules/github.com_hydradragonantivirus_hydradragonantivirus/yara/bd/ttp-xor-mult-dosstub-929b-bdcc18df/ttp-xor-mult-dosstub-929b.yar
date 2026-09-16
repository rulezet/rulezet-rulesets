rule TTP_XOR_MULT_DOSStub_929b {
  strings:
    $key_929b = { c6 f3 [2] b2 eb [2] f5 e9 [2] b2 f8 [2] fc f4 [2] f0 fe [2] e7 f5 [2] fc bb [2] c1 }

  condition:
    any of them
}