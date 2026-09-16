rule TTP_XOR_MULT_DOSStub_091b {
  strings:
    $key_091b = { 5d 73 [2] 29 6b [2] 6e 69 [2] 29 78 [2] 67 74 [2] 6b 7e [2] 7c 75 [2] 67 3b [2] 5a }

  condition:
    any of them
}