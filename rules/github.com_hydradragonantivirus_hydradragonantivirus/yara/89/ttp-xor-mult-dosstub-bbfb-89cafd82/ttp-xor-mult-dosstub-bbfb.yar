rule TTP_XOR_MULT_DOSStub_bbfb {
  strings:
    $key_bbfb = { ef 93 [2] 9b 8b [2] dc 89 [2] 9b 98 [2] d5 94 [2] d9 9e [2] ce 95 [2] d5 db [2] e8 }

  condition:
    any of them
}