rule TTP_XOR_MULT_DOSStub_3753 {
  strings:
    $key_3753 = { 63 3b [2] 17 23 [2] 50 21 [2] 17 30 [2] 59 3c [2] 55 36 [2] 42 3d [2] 59 73 [2] 64 }

  condition:
    any of them
}