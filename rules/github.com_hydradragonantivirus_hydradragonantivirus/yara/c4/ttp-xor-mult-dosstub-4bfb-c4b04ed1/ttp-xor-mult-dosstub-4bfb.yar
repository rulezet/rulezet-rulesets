rule TTP_XOR_MULT_DOSStub_4bfb {
  strings:
    $key_4bfb = { 1f 93 [2] 6b 8b [2] 2c 89 [2] 6b 98 [2] 25 94 [2] 29 9e [2] 3e 95 [2] 25 db [2] 18 }

  condition:
    any of them
}