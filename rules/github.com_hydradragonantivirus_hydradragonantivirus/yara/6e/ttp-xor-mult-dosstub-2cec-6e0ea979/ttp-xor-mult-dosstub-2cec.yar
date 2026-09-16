rule TTP_XOR_MULT_DOSStub_2cec {
  strings:
    $key_2cec = { 78 84 [2] 0c 9c [2] 4b 9e [2] 0c 8f [2] 42 83 [2] 4e 89 [2] 59 82 [2] 42 cc [2] 7f }

  condition:
    any of them
}