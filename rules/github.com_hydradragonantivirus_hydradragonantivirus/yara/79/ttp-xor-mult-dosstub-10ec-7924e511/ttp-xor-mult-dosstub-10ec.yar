rule TTP_XOR_MULT_DOSStub_10ec {
  strings:
    $key_10ec = { 44 84 [2] 30 9c [2] 77 9e [2] 30 8f [2] 7e 83 [2] 72 89 [2] 65 82 [2] 7e cc [2] 43 }

  condition:
    any of them
}