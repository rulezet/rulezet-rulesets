rule TTP_XOR_MULT_DOSStub_6a53 {
  strings:
    $key_6a53 = { 3e 3b [2] 4a 23 [2] 0d 21 [2] 4a 30 [2] 04 3c [2] 08 36 [2] 1f 3d [2] 04 73 [2] 39 }

  condition:
    any of them
}