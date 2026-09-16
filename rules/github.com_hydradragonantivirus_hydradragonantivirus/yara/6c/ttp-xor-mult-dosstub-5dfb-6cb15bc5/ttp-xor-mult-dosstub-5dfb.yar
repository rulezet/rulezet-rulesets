rule TTP_XOR_MULT_DOSStub_5dfb {
  strings:
    $key_5dfb = { 09 93 [2] 7d 8b [2] 3a 89 [2] 7d 98 [2] 33 94 [2] 3f 9e [2] 28 95 [2] 33 db [2] 0e }

  condition:
    any of them
}