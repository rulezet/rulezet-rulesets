rule TTP_XOR_MULT_DOSStub_359d {
  strings:
    $key_359d = { 61 f5 [2] 15 ed [2] 52 ef [2] 15 fe [2] 5b f2 [2] 57 f8 [2] 40 f3 [2] 5b bd [2] 66 }

  condition:
    any of them
}