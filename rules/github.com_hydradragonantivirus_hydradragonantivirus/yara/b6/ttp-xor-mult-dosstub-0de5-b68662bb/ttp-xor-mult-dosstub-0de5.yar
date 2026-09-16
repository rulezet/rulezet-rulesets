rule TTP_XOR_MULT_DOSStub_0de5 {
  strings:
    $key_0de5 = { 59 8d [2] 2d 95 [2] 6a 97 [2] 2d 86 [2] 63 8a [2] 6f 80 [2] 78 8b [2] 63 c5 [2] 5e }

  condition:
    any of them
}