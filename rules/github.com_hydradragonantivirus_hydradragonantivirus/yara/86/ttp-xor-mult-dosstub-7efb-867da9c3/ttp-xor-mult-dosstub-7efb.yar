rule TTP_XOR_MULT_DOSStub_7efb {
  strings:
    $key_7efb = { 2a 93 [2] 5e 8b [2] 19 89 [2] 5e 98 [2] 10 94 [2] 1c 9e [2] 0b 95 [2] 10 db [2] 2d }

  condition:
    any of them
}