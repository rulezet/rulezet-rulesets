rule TTP_XOR_MULT_DOSStub_72ec {
  strings:
    $key_72ec = { 26 84 [2] 52 9c [2] 15 9e [2] 52 8f [2] 1c 83 [2] 10 89 [2] 07 82 [2] 1c cc [2] 21 }

  condition:
    any of them
}