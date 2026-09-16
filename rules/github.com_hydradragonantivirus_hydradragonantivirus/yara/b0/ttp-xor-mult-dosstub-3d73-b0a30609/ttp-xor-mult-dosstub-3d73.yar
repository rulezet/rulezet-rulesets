rule TTP_XOR_MULT_DOSStub_3d73 {
  strings:
    $key_3d73 = { 69 1b [2] 1d 03 [2] 5a 01 [2] 1d 10 [2] 53 1c [2] 5f 16 [2] 48 1d [2] 53 53 [2] 6e }

  condition:
    any of them
}