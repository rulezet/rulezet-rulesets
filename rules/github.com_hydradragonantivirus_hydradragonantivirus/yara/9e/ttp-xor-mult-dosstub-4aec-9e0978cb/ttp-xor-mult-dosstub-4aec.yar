rule TTP_XOR_MULT_DOSStub_4aec {
  strings:
    $key_4aec = { 1e 84 [2] 6a 9c [2] 2d 9e [2] 6a 8f [2] 24 83 [2] 28 89 [2] 3f 82 [2] 24 cc [2] 19 }

  condition:
    any of them
}