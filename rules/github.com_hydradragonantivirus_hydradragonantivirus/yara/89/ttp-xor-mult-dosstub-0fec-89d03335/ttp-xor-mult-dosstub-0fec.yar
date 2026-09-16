rule TTP_XOR_MULT_DOSStub_0fec {
  strings:
    $key_0fec = { 5b 84 [2] 2f 9c [2] 68 9e [2] 2f 8f [2] 61 83 [2] 6d 89 [2] 7a 82 [2] 61 cc [2] 5c }

  condition:
    any of them
}