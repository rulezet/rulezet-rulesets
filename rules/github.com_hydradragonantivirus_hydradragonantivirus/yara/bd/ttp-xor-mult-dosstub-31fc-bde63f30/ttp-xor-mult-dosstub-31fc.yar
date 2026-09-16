rule TTP_XOR_MULT_DOSStub_31fc {
  strings:
    $key_31fc = { 65 94 [2] 11 8c [2] 56 8e [2] 11 9f [2] 5f 93 [2] 53 99 [2] 44 92 [2] 5f dc [2] 62 }

  condition:
    any of them
}