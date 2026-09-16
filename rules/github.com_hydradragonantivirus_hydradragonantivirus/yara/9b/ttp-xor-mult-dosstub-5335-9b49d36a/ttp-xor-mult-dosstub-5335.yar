rule TTP_XOR_MULT_DOSStub_5335 {
  strings:
    $key_5335 = { 07 5d [2] 73 45 [2] 34 47 [2] 73 56 [2] 3d 5a [2] 31 50 [2] 26 5b [2] 3d 15 [2] 00 }

  condition:
    any of them
}