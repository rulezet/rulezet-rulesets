rule TTP_XOR_MULT_DOSStub_071b {
  strings:
    $key_071b = { 53 73 [2] 27 6b [2] 60 69 [2] 27 78 [2] 69 74 [2] 65 7e [2] 72 75 [2] 69 3b [2] 54 }

  condition:
    any of them
}