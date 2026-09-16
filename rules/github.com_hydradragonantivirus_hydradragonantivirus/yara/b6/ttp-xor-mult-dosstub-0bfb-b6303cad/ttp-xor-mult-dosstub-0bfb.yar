rule TTP_XOR_MULT_DOSStub_0bfb {
  strings:
    $key_0bfb = { 5f 93 [2] 2b 8b [2] 6c 89 [2] 2b 98 [2] 65 94 [2] 69 9e [2] 7e 95 [2] 65 db [2] 58 }

  condition:
    any of them
}