rule TTP_XOR_MULT_DOSStub_3d23 {
  strings:
    $key_3d23 = { 69 4b [2] 1d 53 [2] 5a 51 [2] 1d 40 [2] 53 4c [2] 5f 46 [2] 48 4d [2] 53 03 [2] 6e }

  condition:
    any of them
}