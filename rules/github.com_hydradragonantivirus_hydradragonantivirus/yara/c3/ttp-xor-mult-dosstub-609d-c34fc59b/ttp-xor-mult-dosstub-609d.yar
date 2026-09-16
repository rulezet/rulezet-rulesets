rule TTP_XOR_MULT_DOSStub_609d {
  strings:
    $key_609d = { 34 f5 [2] 40 ed [2] 07 ef [2] 40 fe [2] 0e f2 [2] 02 f8 [2] 15 f3 [2] 0e bd [2] 33 }

  condition:
    any of them
}