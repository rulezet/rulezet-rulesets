rule TTP_XOR_MULT_DOSStub_bb61 {
  strings:
    $key_bb61 = { ef 09 [2] 9b 11 [2] dc 13 [2] 9b 02 [2] d5 0e [2] d9 04 [2] ce 0f [2] d5 41 [2] e8 }

  condition:
    any of them
}