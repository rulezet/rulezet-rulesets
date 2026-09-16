rule TTP_XOR_MULT_DOSStub_bbfc {
  strings:
    $key_bbfc = { ef 94 [2] 9b 8c [2] dc 8e [2] 9b 9f [2] d5 93 [2] d9 99 [2] ce 92 [2] d5 dc [2] e8 }

  condition:
    any of them
}