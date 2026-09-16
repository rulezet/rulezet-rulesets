rule TTP_XOR_MULT_DOSStub_6603 {
  strings:
    $key_6603 = { 32 6b [2] 46 73 [2] 01 71 [2] 46 60 [2] 08 6c [2] 04 66 [2] 13 6d [2] 08 23 [2] 35 }

  condition:
    any of them
}