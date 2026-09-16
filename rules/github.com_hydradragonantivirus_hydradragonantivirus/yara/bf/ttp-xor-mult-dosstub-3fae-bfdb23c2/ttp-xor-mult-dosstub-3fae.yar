rule TTP_XOR_MULT_DOSStub_3fae {
  strings:
    $key_3fae = { 6b c6 [2] 1f de [2] 58 dc [2] 1f cd [2] 51 c1 [2] 5d cb [2] 4a c0 [2] 51 8e [2] 6c }

  condition:
    any of them
}