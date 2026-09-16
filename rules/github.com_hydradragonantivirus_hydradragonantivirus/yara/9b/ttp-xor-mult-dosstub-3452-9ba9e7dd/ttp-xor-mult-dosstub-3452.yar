rule TTP_XOR_MULT_DOSStub_3452 {
  strings:
    $key_3452 = { 60 3a [2] 14 22 [2] 53 20 [2] 14 31 [2] 5a 3d [2] 56 37 [2] 41 3c [2] 5a 72 [2] 67 }

  condition:
    any of them
}