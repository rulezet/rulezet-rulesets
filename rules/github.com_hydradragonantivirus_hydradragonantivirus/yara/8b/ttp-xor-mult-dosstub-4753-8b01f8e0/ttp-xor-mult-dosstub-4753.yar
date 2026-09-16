rule TTP_XOR_MULT_DOSStub_4753 {
  strings:
    $key_4753 = { 13 3b [2] 67 23 [2] 20 21 [2] 67 30 [2] 29 3c [2] 25 36 [2] 32 3d [2] 29 73 [2] 14 }

  condition:
    any of them
}