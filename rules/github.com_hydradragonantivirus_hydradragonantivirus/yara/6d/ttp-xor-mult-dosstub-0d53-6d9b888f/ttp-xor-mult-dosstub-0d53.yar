rule TTP_XOR_MULT_DOSStub_0d53 {
  strings:
    $key_0d53 = { 59 3b [2] 2d 23 [2] 6a 21 [2] 2d 30 [2] 63 3c [2] 6f 36 [2] 78 3d [2] 63 73 [2] 5e }

  condition:
    any of them
}