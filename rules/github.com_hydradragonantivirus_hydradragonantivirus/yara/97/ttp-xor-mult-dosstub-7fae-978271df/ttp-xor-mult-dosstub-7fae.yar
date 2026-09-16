rule TTP_XOR_MULT_DOSStub_7fae {
  strings:
    $key_7fae = { 2b c6 [2] 5f de [2] 18 dc [2] 5f cd [2] 11 c1 [2] 1d cb [2] 0a c0 [2] 11 8e [2] 2c }

  condition:
    any of them
}