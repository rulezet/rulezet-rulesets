rule TTP_XOR_MULT_DOSStub_1aec {
  strings:
    $key_1aec = { 4e 84 [2] 3a 9c [2] 7d 9e [2] 3a 8f [2] 74 83 [2] 78 89 [2] 6f 82 [2] 74 cc [2] 49 }

  condition:
    any of them
}