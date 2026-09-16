rule TTP_XOR_MULT_DOSStub_bb6e {
  strings:
    $key_bb6e = { ef 06 [2] 9b 1e [2] dc 1c [2] 9b 0d [2] d5 01 [2] d9 0b [2] ce 00 [2] d5 4e [2] e8 }

  condition:
    any of them
}