rule TTP_XOR_MULT_DOSStub_2d23 {
  strings:
    $key_2d23 = { 79 4b [2] 0d 53 [2] 4a 51 [2] 0d 40 [2] 43 4c [2] 4f 46 [2] 58 4d [2] 43 03 [2] 7e }

  condition:
    any of them
}