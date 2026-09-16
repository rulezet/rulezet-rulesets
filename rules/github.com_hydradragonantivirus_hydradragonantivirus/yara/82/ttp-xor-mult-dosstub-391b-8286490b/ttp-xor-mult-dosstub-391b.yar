rule TTP_XOR_MULT_DOSStub_391b {
  strings:
    $key_391b = { 6d 73 [2] 19 6b [2] 5e 69 [2] 19 78 [2] 57 74 [2] 5b 7e [2] 4c 75 [2] 57 3b [2] 6a }

  condition:
    any of them
}