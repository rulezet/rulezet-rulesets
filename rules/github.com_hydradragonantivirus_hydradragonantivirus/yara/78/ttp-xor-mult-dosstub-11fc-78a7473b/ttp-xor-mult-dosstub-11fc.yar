rule TTP_XOR_MULT_DOSStub_11fc {
  strings:
    $key_11fc = { 45 94 [2] 31 8c [2] 76 8e [2] 31 9f [2] 7f 93 [2] 73 99 [2] 64 92 [2] 7f dc [2] 42 }

  condition:
    any of them
}