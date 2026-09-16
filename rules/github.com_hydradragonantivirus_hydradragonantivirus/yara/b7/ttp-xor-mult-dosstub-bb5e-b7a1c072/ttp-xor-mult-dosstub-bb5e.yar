rule TTP_XOR_MULT_DOSStub_bb5e {
  strings:
    $key_bb5e = { ef 36 [2] 9b 2e [2] dc 2c [2] 9b 3d [2] d5 31 [2] d9 3b [2] ce 30 [2] d5 7e [2] e8 }

  condition:
    any of them
}