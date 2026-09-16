rule TTP_XOR_MULT_DOSStub_72e5 {
  strings:
    $key_72e5 = { 26 8d [2] 52 95 [2] 15 97 [2] 52 86 [2] 1c 8a [2] 10 80 [2] 07 8b [2] 1c c5 [2] 21 }

  condition:
    any of them
}