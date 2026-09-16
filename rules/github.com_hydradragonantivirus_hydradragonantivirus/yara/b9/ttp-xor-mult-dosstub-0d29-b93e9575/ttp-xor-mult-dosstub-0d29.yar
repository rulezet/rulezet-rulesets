rule TTP_XOR_MULT_DOSStub_0d29 {
  strings:
    $key_0d29 = { 59 41 [2] 2d 59 [2] 6a 5b [2] 2d 4a [2] 63 46 [2] 6f 4c [2] 78 47 [2] 63 09 [2] 5e }

  condition:
    any of them
}