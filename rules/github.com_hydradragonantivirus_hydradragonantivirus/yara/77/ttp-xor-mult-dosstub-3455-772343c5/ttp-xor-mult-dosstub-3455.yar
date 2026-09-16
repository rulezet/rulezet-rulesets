rule TTP_XOR_MULT_DOSStub_3455 {
  strings:
    $key_3455 = { 60 3d [2] 14 25 [2] 53 27 [2] 14 36 [2] 5a 3a [2] 56 30 [2] 41 3b [2] 5a 75 [2] 67 }

  condition:
    any of them
}