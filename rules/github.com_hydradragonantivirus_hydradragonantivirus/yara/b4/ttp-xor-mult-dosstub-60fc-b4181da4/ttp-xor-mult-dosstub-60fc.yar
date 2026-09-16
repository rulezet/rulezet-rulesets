rule TTP_XOR_MULT_DOSStub_60fc {
  strings:
    $key_60fc = { 34 94 [2] 40 8c [2] 07 8e [2] 40 9f [2] 0e 93 [2] 02 99 [2] 15 92 [2] 0e dc [2] 33 }

  condition:
    any of them
}