rule TTP_XOR_MULT_DOSStub_4fec {
  strings:
    $key_4fec = { 1b 84 [2] 6f 9c [2] 28 9e [2] 6f 8f [2] 21 83 [2] 2d 89 [2] 3a 82 [2] 21 cc [2] 1c }

  condition:
    any of them
}