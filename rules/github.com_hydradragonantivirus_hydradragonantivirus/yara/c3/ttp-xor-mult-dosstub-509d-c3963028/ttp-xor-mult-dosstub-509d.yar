rule TTP_XOR_MULT_DOSStub_509d {
  strings:
    $key_509d = { 04 f5 [2] 70 ed [2] 37 ef [2] 70 fe [2] 3e f2 [2] 32 f8 [2] 25 f3 [2] 3e bd [2] 03 }

  condition:
    any of them
}