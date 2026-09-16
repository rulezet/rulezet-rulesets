rule TTP_XOR_MULT_DOSStub_093b {
  strings:
    $key_093b = { 5d 53 [2] 29 4b [2] 6e 49 [2] 29 58 [2] 67 54 [2] 6b 5e [2] 7c 55 [2] 67 1b [2] 5a }

  condition:
    any of them
}