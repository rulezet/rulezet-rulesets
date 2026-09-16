rule TTP_XOR_MULT_DOSStub_12e3 {
  strings:
    $key_12e3 = { 46 8b [2] 32 93 [2] 75 91 [2] 32 80 [2] 7c 8c [2] 70 86 [2] 67 8d [2] 7c c3 [2] 41 }

  condition:
    any of them
}