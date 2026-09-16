rule TTP_XOR_MULT_DOSStub_ff88 {
  strings:
    $key_ff88 = { ab e0 [2] df f8 [2] 98 fa [2] df eb [2] 91 e7 [2] 9d ed [2] 8a e6 [2] 91 a8 [2] ac }

  condition:
    any of them
}