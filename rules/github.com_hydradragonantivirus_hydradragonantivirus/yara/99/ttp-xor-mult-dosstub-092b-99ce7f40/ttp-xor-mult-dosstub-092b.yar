rule TTP_XOR_MULT_DOSStub_092b {
  strings:
    $key_092b = { 5d 43 [2] 29 5b [2] 6e 59 [2] 29 48 [2] 67 44 [2] 6b 4e [2] 7c 45 [2] 67 0b [2] 5a }

  condition:
    any of them
}