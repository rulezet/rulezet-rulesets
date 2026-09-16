rule TTP_XOR_MULT_DOSStub_38fc {
  strings:
    $key_38fc = { 6c 94 [2] 18 8c [2] 5f 8e [2] 18 9f [2] 56 93 [2] 5a 99 [2] 4d 92 [2] 56 dc [2] 6b }

  condition:
    any of them
}