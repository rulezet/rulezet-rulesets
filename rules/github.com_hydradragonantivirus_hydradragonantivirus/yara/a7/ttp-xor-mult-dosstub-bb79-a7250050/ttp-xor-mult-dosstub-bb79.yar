rule TTP_XOR_MULT_DOSStub_bb79 {
  strings:
    $key_bb79 = { ef 11 [2] 9b 09 [2] dc 0b [2] 9b 1a [2] d5 16 [2] d9 1c [2] ce 17 [2] d5 59 [2] e8 }

  condition:
    any of them
}