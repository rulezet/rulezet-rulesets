rule TTP_XOR_MULT_DOSStub_bb60 {
  strings:
    $key_bb60 = { ef 08 [2] 9b 10 [2] dc 12 [2] 9b 03 [2] d5 0f [2] d9 05 [2] ce 0e [2] d5 40 [2] e8 }

  condition:
    any of them
}