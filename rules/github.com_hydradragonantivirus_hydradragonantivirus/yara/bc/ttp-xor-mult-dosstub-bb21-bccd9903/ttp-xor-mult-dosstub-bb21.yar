rule TTP_XOR_MULT_DOSStub_bb21 {
  strings:
    $key_bb21 = { ef 49 [2] 9b 51 [2] dc 53 [2] 9b 42 [2] d5 4e [2] d9 44 [2] ce 4f [2] d5 01 [2] e8 }

  condition:
    any of them
}