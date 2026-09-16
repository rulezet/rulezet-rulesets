rule TTP_XOR_MULT_DOSStub_3cec {
  strings:
    $key_3cec = { 68 84 [2] 1c 9c [2] 5b 9e [2] 1c 8f [2] 52 83 [2] 5e 89 [2] 49 82 [2] 52 cc [2] 6f }

  condition:
    any of them
}