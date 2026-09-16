rule TTP_XOR_MULT_DOSStub_0752 {
  strings:
    $key_0752 = { 53 3a [2] 27 22 [2] 60 20 [2] 27 31 [2] 69 3d [2] 65 37 [2] 72 3c [2] 69 72 [2] 54 }

  condition:
    any of them
}