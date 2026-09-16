rule TTP_XOR_MULT_DOSStub_471b {
  strings:
    $key_471b = { 13 73 [2] 67 6b [2] 20 69 [2] 67 78 [2] 29 74 [2] 25 7e [2] 32 75 [2] 29 3b [2] 14 }

  condition:
    any of them
}