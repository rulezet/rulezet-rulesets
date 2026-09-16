rule TTP_XOR_MULT_DOSStub_25ec {
  strings:
    $key_25ec = { 71 84 [2] 05 9c [2] 42 9e [2] 05 8f [2] 4b 83 [2] 47 89 [2] 50 82 [2] 4b cc [2] 76 }

  condition:
    any of them
}