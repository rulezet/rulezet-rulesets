rule TTP_XOR_MULT_DOSStub_3873 {
  strings:
    $key_3873 = { 6c 1b [2] 18 03 [2] 5f 01 [2] 18 10 [2] 56 1c [2] 5a 16 [2] 4d 1d [2] 56 53 [2] 6b }

  condition:
    any of them
}