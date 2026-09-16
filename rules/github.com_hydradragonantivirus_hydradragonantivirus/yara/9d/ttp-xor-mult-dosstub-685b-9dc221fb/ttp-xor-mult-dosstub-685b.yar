rule TTP_XOR_MULT_DOSStub_685b {
  strings:
    $key_685b = { 3c 33 [2] 48 2b [2] 0f 29 [2] 48 38 [2] 06 34 [2] 0a 3e [2] 1d 35 [2] 06 7b [2] 3b }

  condition:
    any of them
}