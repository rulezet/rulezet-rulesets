rule TTP_XOR_MULT_DOSStub_2bfb {
  strings:
    $key_2bfb = { 7f 93 [2] 0b 8b [2] 4c 89 [2] 0b 98 [2] 45 94 [2] 49 9e [2] 5e 95 [2] 45 db [2] 78 }

  condition:
    any of them
}