rule TTP_XOR_MULT_DOSStub_679d {
  strings:
    $key_679d = { 33 f5 [2] 47 ed [2] 00 ef [2] 47 fe [2] 09 f2 [2] 05 f8 [2] 12 f3 [2] 09 bd [2] 34 }

  condition:
    any of them
}