rule TTP_XOR_MULT_DOSStub_4fae {
  strings:
    $key_4fae = { 1b c6 [2] 6f de [2] 28 dc [2] 6f cd [2] 21 c1 [2] 2d cb [2] 3a c0 [2] 21 8e [2] 1c }

  condition:
    any of them
}