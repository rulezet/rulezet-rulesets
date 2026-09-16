rule TTP_XOR_MULT_DOSStub_0afb {
  strings:
    $key_0afb = { 5e 93 [2] 2a 8b [2] 6d 89 [2] 2a 98 [2] 64 94 [2] 68 9e [2] 7f 95 [2] 64 db [2] 59 }

  condition:
    any of them
}