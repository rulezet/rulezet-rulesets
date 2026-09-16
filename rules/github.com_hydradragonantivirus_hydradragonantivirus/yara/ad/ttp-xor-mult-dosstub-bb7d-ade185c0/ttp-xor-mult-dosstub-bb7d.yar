rule TTP_XOR_MULT_DOSStub_bb7d {
  strings:
    $key_bb7d = { ef 15 [2] 9b 0d [2] dc 0f [2] 9b 1e [2] d5 12 [2] d9 18 [2] ce 13 [2] d5 5d [2] e8 }

  condition:
    any of them
}