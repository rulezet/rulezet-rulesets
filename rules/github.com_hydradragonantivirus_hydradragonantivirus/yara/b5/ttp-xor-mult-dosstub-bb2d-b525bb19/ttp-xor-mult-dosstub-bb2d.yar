rule TTP_XOR_MULT_DOSStub_bb2d {
  strings:
    $key_bb2d = { ef 45 [2] 9b 5d [2] dc 5f [2] 9b 4e [2] d5 42 [2] d9 48 [2] ce 43 [2] d5 0d [2] e8 }

  condition:
    any of them
}