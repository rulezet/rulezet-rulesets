rule TTP_XOR_MULT_DOSStub_2752 {
  strings:
    $key_2752 = { 73 3a [2] 07 22 [2] 40 20 [2] 07 31 [2] 49 3d [2] 45 37 [2] 52 3c [2] 49 72 [2] 74 }

  condition:
    any of them
}