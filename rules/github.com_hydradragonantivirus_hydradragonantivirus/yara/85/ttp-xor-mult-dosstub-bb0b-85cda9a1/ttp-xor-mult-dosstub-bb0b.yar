rule TTP_XOR_MULT_DOSStub_bb0b {
  strings:
    $key_bb0b = { ef 63 [2] 9b 7b [2] dc 79 [2] 9b 68 [2] d5 64 [2] d9 6e [2] ce 65 [2] d5 2b [2] e8 }

  condition:
    any of them
}