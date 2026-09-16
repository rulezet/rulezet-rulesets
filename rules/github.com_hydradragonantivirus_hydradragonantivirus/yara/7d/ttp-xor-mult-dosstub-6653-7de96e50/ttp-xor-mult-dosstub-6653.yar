rule TTP_XOR_MULT_DOSStub_6653 {
  strings:
    $key_6653 = { 32 3b [2] 46 23 [2] 01 21 [2] 46 30 [2] 08 3c [2] 04 36 [2] 13 3d [2] 08 73 [2] 35 }

  condition:
    any of them
}