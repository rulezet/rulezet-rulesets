rule TTP_XOR_MULT_DOSStub_6633 {
  strings:
    $key_6633 = { 32 5b [2] 46 43 [2] 01 41 [2] 46 50 [2] 08 5c [2] 04 56 [2] 13 5d [2] 08 13 [2] 35 }

  condition:
    any of them
}