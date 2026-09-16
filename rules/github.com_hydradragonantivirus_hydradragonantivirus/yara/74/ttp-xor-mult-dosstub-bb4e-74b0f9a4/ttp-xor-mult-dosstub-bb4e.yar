rule TTP_XOR_MULT_DOSStub_bb4e {
  strings:
    $key_bb4e = { ef 26 [2] 9b 3e [2] dc 3c [2] 9b 2d [2] d5 21 [2] d9 2b [2] ce 20 [2] d5 6e [2] e8 }

  condition:
    any of them
}