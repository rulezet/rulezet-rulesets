rule TTP_XOR_MULT_DOSStub_0de8 {
  strings:
    $key_0de8 = { 59 80 [2] 2d 98 [2] 6a 9a [2] 2d 8b [2] 63 87 [2] 6f 8d [2] 78 86 [2] 63 c8 [2] 5e }

  condition:
    any of them
}