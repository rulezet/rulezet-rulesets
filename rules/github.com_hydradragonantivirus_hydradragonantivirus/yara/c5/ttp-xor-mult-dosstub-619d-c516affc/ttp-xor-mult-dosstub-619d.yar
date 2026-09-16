rule TTP_XOR_MULT_DOSStub_619d {
  strings:
    $key_619d = { 35 f5 [2] 41 ed [2] 06 ef [2] 41 fe [2] 0f f2 [2] 03 f8 [2] 14 f3 [2] 0f bd [2] 32 }

  condition:
    any of them
}