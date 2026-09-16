rule TTP_XOR_MULT_DOSStub_4eec {
  strings:
    $key_4eec = { 1a 84 [2] 6e 9c [2] 29 9e [2] 6e 8f [2] 20 83 [2] 2c 89 [2] 3b 82 [2] 20 cc [2] 1d }

  condition:
    any of them
}