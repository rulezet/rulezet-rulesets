rule TTP_XOR_MULT_DOSStub_6cec {
  strings:
    $key_6cec = { 38 84 [2] 4c 9c [2] 0b 9e [2] 4c 8f [2] 02 83 [2] 0e 89 [2] 19 82 [2] 02 cc [2] 3f }

  condition:
    any of them
}