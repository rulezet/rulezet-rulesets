rule TTP_XOR_MULT_DOSStub_3f88 {
  strings:
    $key_3f88 = { 6b e0 [2] 1f f8 [2] 58 fa [2] 1f eb [2] 51 e7 [2] 5d ed [2] 4a e6 [2] 51 a8 [2] 6c }

  condition:
    any of them
}