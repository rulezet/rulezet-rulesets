rule TTP_XOR_MULT_DOSStub_36ec {
  strings:
    $key_36ec = { 62 84 [2] 16 9c [2] 51 9e [2] 16 8f [2] 58 83 [2] 54 89 [2] 43 82 [2] 58 cc [2] 65 }

  condition:
    any of them
}