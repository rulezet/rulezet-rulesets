rule TTP_XOR_MULT_DOSStub_1f3b {
  strings:
    $key_1f3b = { 4b 53 [2] 3f 4b [2] 78 49 [2] 3f 58 [2] 71 54 [2] 7d 5e [2] 6a 55 [2] 71 1b [2] 4c }

  condition:
    any of them
}