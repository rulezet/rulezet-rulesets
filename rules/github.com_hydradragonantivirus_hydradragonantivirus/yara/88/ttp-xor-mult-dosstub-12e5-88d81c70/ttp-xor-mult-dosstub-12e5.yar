rule TTP_XOR_MULT_DOSStub_12e5 {
  strings:
    $key_12e5 = { 46 8d [2] 32 95 [2] 75 97 [2] 32 86 [2] 7c 8a [2] 70 80 [2] 67 8b [2] 7c c5 [2] 41 }

  condition:
    any of them
}