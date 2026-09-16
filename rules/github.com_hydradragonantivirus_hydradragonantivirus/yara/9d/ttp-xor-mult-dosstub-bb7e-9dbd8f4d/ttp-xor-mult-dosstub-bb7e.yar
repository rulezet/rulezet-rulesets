rule TTP_XOR_MULT_DOSStub_bb7e {
  strings:
    $key_bb7e = { ef 16 [2] 9b 0e [2] dc 0c [2] 9b 1d [2] d5 11 [2] d9 1b [2] ce 10 [2] d5 5e [2] e8 }

  condition:
    any of them
}