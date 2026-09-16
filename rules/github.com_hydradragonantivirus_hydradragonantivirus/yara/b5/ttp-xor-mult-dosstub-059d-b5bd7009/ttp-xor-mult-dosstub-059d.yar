rule TTP_XOR_MULT_DOSStub_059d {
  strings:
    $key_059d = { 51 f5 [2] 25 ed [2] 62 ef [2] 25 fe [2] 6b f2 [2] 67 f8 [2] 70 f3 [2] 6b bd [2] 56 }

  condition:
    any of them
}