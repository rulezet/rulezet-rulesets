rule TTP_XOR_MULT_DOSStub_1d73 {
  strings:
    $key_1d73 = { 49 1b [2] 3d 03 [2] 7a 01 [2] 3d 10 [2] 73 1c [2] 7f 16 [2] 68 1d [2] 73 53 [2] 4e }

  condition:
    any of them
}