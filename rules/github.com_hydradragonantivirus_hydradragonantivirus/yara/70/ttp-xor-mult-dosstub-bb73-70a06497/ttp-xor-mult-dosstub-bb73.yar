rule TTP_XOR_MULT_DOSStub_bb73 {
  strings:
    $key_bb73 = { ef 1b [2] 9b 03 [2] dc 01 [2] 9b 10 [2] d5 1c [2] d9 16 [2] ce 1d [2] d5 53 [2] e8 }

  condition:
    any of them
}