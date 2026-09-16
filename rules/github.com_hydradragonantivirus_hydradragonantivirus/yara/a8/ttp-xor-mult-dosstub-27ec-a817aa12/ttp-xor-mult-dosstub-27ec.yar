rule TTP_XOR_MULT_DOSStub_27ec {
  strings:
    $key_27ec = { 73 84 [2] 07 9c [2] 40 9e [2] 07 8f [2] 49 83 [2] 45 89 [2] 52 82 [2] 49 cc [2] 74 }

  condition:
    any of them
}