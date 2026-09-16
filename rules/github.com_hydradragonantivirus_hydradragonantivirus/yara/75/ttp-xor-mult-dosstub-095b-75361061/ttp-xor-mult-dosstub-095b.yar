rule TTP_XOR_MULT_DOSStub_095b {
  strings:
    $key_095b = { 5d 33 [2] 29 2b [2] 6e 29 [2] 29 38 [2] 67 34 [2] 6b 3e [2] 7c 35 [2] 67 7b [2] 5a }

  condition:
    any of them
}