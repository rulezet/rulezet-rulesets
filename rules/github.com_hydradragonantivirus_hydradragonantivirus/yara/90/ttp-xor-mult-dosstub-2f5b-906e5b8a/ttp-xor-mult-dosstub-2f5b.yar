rule TTP_XOR_MULT_DOSStub_2f5b {
  strings:
    $key_2f5b = { 7b 33 [2] 0f 2b [2] 48 29 [2] 0f 38 [2] 41 34 [2] 4d 3e [2] 5a 35 [2] 41 7b [2] 7c }

  condition:
    any of them
}