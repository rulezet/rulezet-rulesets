rule TTP_XOR_MULT_DOSStub_5355 {
  strings:
    $key_5355 = { 07 3d [2] 73 25 [2] 34 27 [2] 73 36 [2] 3d 3a [2] 31 30 [2] 26 3b [2] 3d 75 [2] 00 }

  condition:
    any of them
}