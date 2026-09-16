rule TTP_XOR_MULT_DOSStub_0753 {
  strings:
    $key_0753 = { 53 3b [2] 27 23 [2] 60 21 [2] 27 30 [2] 69 3c [2] 65 36 [2] 72 3d [2] 69 73 [2] 54 }

  condition:
    any of them
}