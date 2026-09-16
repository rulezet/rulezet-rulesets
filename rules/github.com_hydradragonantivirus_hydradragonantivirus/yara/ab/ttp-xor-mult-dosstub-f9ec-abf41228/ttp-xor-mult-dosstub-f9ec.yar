rule TTP_XOR_MULT_DOSStub_f9ec {
  strings:
    $key_f9ec = { ad 84 [2] d9 9c [2] 9e 9e [2] d9 8f [2] 97 83 [2] 9b 89 [2] 8c 82 [2] 97 cc [2] aa }

  condition:
    any of them
}