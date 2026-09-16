rule TTP_XOR_MULT_DOSStub_bb3b {
  strings:
    $key_bb3b = { ef 53 [2] 9b 4b [2] dc 49 [2] 9b 58 [2] d5 54 [2] d9 5e [2] ce 55 [2] d5 1b [2] e8 }

  condition:
    any of them
}