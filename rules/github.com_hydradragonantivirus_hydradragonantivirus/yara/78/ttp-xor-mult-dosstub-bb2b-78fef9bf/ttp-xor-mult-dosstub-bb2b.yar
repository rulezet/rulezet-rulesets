rule TTP_XOR_MULT_DOSStub_bb2b {
  strings:
    $key_bb2b = { ef 43 [2] 9b 5b [2] dc 59 [2] 9b 48 [2] d5 44 [2] d9 4e [2] ce 45 [2] d5 0b [2] e8 }

  condition:
    any of them
}