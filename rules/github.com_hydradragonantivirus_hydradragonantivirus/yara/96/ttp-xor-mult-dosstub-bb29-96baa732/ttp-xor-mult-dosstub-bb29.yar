rule TTP_XOR_MULT_DOSStub_bb29 {
  strings:
    $key_bb29 = { ef 41 [2] 9b 59 [2] dc 5b [2] 9b 4a [2] d5 46 [2] d9 4c [2] ce 47 [2] d5 09 [2] e8 }

  condition:
    any of them
}