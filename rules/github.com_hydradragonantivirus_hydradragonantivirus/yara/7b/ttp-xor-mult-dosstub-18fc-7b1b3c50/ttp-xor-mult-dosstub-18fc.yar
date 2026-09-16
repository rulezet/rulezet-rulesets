rule TTP_XOR_MULT_DOSStub_18fc {
  strings:
    $key_18fc = { 4c 94 [2] 38 8c [2] 7f 8e [2] 38 9f [2] 76 93 [2] 7a 99 [2] 6d 92 [2] 76 dc [2] 4b }

  condition:
    any of them
}