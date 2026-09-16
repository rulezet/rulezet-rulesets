rule TTP_XOR_MULT_DOSStub_4cec {
  strings:
    $key_4cec = { 18 84 [2] 6c 9c [2] 2b 9e [2] 6c 8f [2] 22 83 [2] 2e 89 [2] 39 82 [2] 22 cc [2] 1f }

  condition:
    any of them
}