rule TTP_XOR_MULT_DOSStub_22e3 {
  strings:
    $key_22e3 = { 76 8b [2] 02 93 [2] 45 91 [2] 02 80 [2] 4c 8c [2] 40 86 [2] 57 8d [2] 4c c3 [2] 71 }

  condition:
    any of them
}