rule TTP_XOR_MULT_DOSStub_181b {
  strings:
    $key_181b = { 4c 73 [2] 38 6b [2] 7f 69 [2] 38 78 [2] 76 74 [2] 7a 7e [2] 6d 75 [2] 76 3b [2] 4b }

  condition:
    any of them
}