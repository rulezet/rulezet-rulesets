rule TTP_XOR_MULT_DOSStub_bb5d {
  strings:
    $key_bb5d = { ef 35 [2] 9b 2d [2] dc 2f [2] 9b 3e [2] d5 32 [2] d9 38 [2] ce 33 [2] d5 7d [2] e8 }

  condition:
    any of them
}