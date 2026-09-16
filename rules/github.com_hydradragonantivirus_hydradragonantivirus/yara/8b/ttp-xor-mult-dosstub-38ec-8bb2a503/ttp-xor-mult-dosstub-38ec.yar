rule TTP_XOR_MULT_DOSStub_38ec {
  strings:
    $key_38ec = { 6c 84 [2] 18 9c [2] 5f 9e [2] 18 8f [2] 56 83 [2] 5a 89 [2] 4d 82 [2] 56 cc [2] 6b }

  condition:
    any of them
}