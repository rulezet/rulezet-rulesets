rule TTP_XOR_MULT_DOSStub_4f23 {
  strings:
    $key_4f23 = { 1b 4b [2] 6f 53 [2] 28 51 [2] 6f 40 [2] 21 4c [2] 2d 46 [2] 3a 4d [2] 21 03 [2] 1c }

  condition:
    any of them
}