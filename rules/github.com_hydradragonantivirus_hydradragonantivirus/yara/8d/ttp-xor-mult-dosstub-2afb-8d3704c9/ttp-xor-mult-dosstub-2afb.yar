rule TTP_XOR_MULT_DOSStub_2afb {
  strings:
    $key_2afb = { 7e 93 [2] 0a 8b [2] 4d 89 [2] 0a 98 [2] 44 94 [2] 48 9e [2] 5f 95 [2] 44 db [2] 79 }

  condition:
    any of them
}