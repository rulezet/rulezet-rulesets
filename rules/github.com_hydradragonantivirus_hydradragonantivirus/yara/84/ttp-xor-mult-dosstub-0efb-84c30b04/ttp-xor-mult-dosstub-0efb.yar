rule TTP_XOR_MULT_DOSStub_0efb {
  strings:
    $key_0efb = { 5a 93 [2] 2e 8b [2] 69 89 [2] 2e 98 [2] 60 94 [2] 6c 9e [2] 7b 95 [2] 60 db [2] 5d }

  condition:
    any of them
}