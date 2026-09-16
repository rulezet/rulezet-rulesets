rule TTP_XOR_MULT_DOSStub_2a53 {
  strings:
    $key_2a53 = { 7e 3b [2] 0a 23 [2] 4d 21 [2] 0a 30 [2] 44 3c [2] 48 36 [2] 5f 3d [2] 44 73 [2] 79 }

  condition:
    any of them
}