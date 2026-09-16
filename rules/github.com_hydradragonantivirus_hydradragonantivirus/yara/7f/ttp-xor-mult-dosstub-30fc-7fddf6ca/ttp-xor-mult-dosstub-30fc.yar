rule TTP_XOR_MULT_DOSStub_30fc {
  strings:
    $key_30fc = { 64 94 [2] 10 8c [2] 57 8e [2] 10 9f [2] 5e 93 [2] 52 99 [2] 45 92 [2] 5e dc [2] 63 }

  condition:
    any of them
}