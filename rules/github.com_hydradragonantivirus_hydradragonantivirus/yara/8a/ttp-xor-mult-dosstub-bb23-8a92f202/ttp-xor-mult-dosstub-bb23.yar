rule TTP_XOR_MULT_DOSStub_bb23 {
  strings:
    $key_bb23 = { ef 4b [2] 9b 53 [2] dc 51 [2] 9b 40 [2] d5 4c [2] d9 46 [2] ce 4d [2] d5 03 [2] e8 }

  condition:
    any of them
}