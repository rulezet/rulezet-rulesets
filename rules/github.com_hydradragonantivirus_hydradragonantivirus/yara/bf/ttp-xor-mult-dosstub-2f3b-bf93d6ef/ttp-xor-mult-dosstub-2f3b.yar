rule TTP_XOR_MULT_DOSStub_2f3b {
  strings:
    $key_2f3b = { 7b 53 [2] 0f 4b [2] 48 49 [2] 0f 58 [2] 41 54 [2] 4d 5e [2] 5a 55 [2] 41 1b [2] 7c }

  condition:
    any of them
}