rule TTP_XOR_MULT_DOSStub_bb4c {
  strings:
    $key_bb4c = { ef 24 [2] 9b 3c [2] dc 3e [2] 9b 2f [2] d5 23 [2] d9 29 [2] ce 22 [2] d5 6c [2] e8 }

  condition:
    any of them
}