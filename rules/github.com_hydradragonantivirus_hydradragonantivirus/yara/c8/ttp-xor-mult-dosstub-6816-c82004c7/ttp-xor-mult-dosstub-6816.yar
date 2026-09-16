rule TTP_XOR_MULT_DOSStub_6816 {
  strings:
    $key_6816 = { 3c 7e [2] 48 66 [2] 0f 64 [2] 48 75 [2] 06 79 [2] 0a 73 [2] 1d 78 [2] 06 36 [2] 3b }

  condition:
    any of them
}