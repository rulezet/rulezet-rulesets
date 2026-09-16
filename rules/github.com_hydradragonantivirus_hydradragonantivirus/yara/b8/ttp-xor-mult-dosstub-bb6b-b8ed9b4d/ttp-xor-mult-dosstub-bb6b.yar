rule TTP_XOR_MULT_DOSStub_bb6b {
  strings:
    $key_bb6b = { ef 03 [2] 9b 1b [2] dc 19 [2] 9b 08 [2] d5 04 [2] d9 0e [2] ce 05 [2] d5 4b [2] e8 }

  condition:
    any of them
}