rule TTP_XOR_MULT_DOSStub_3f4b {
  strings:
    $key_3f4b = { 6b 23 [2] 1f 3b [2] 58 39 [2] 1f 28 [2] 51 24 [2] 5d 2e [2] 4a 25 [2] 51 6b [2] 6c }

  condition:
    any of them
}