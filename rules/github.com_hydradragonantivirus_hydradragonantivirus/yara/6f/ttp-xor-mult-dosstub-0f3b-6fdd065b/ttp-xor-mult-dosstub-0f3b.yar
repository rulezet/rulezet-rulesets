rule TTP_XOR_MULT_DOSStub_0f3b {
  strings:
    $key_0f3b = { 5b 53 [2] 2f 4b [2] 68 49 [2] 2f 58 [2] 61 54 [2] 6d 5e [2] 7a 55 [2] 61 1b [2] 5c }

  condition:
    any of them
}