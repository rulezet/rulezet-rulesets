rule TTP_XOR_MULT_DOSStub_e7ec {
  strings:
    $key_e7ec = { b3 84 [2] c7 9c [2] 80 9e [2] c7 8f [2] 89 83 [2] 85 89 [2] 92 82 [2] 89 cc [2] b4 }

  condition:
    any of them
}