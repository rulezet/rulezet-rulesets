rule TTP_XOR_MULT_DOSStub_662c {
  strings:
    $key_662c = { 32 44 [2] 46 5c [2] 01 5e [2] 46 4f [2] 08 43 [2] 04 49 [2] 13 42 [2] 08 0c [2] 35 }

  condition:
    any of them
}