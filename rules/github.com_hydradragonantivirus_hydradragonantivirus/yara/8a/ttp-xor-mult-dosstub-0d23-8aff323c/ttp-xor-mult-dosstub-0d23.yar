rule TTP_XOR_MULT_DOSStub_0d23 {
  strings:
    $key_0d23 = { 59 4b [2] 2d 53 [2] 6a 51 [2] 2d 40 [2] 63 4c [2] 6f 46 [2] 78 4d [2] 63 03 [2] 5e }

  condition:
    any of them
}