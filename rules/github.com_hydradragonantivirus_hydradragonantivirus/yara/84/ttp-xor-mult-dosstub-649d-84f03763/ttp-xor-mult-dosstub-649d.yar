rule TTP_XOR_MULT_DOSStub_649d {
  strings:
    $key_649d = { 30 f5 [2] 44 ed [2] 03 ef [2] 44 fe [2] 0a f2 [2] 06 f8 [2] 11 f3 [2] 0a bd [2] 37 }

  condition:
    any of them
}