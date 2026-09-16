rule TTP_XOR_MULT_DOSStub_bb69 {
  strings:
    $key_bb69 = { ef 01 [2] 9b 19 [2] dc 1b [2] 9b 0a [2] d5 06 [2] d9 0c [2] ce 07 [2] d5 49 [2] e8 }

  condition:
    any of them
}