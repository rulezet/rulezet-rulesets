rule TTP_XOR_MULT_DOSStub_6dfb {
  strings:
    $key_6dfb = { 39 93 [2] 4d 8b [2] 0a 89 [2] 4d 98 [2] 03 94 [2] 0f 9e [2] 18 95 [2] 03 db [2] 3e }

  condition:
    any of them
}