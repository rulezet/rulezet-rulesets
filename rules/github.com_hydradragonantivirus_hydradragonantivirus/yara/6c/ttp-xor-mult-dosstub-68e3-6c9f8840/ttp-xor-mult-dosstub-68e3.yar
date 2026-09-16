rule TTP_XOR_MULT_DOSStub_68e3 {
  strings:
    $key_68e3 = { 3c 8b [2] 48 93 [2] 0f 91 [2] 48 80 [2] 06 8c [2] 0a 86 [2] 1d 8d [2] 06 c3 [2] 3b }

  condition:
    any of them
}