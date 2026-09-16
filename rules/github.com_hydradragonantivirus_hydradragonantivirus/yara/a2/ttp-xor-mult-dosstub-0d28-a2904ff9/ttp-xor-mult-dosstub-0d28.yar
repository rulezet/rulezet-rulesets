rule TTP_XOR_MULT_DOSStub_0d28 {
  strings:
    $key_0d28 = { 59 40 [2] 2d 58 [2] 6a 5a [2] 2d 4b [2] 63 47 [2] 6f 4d [2] 78 46 [2] 63 08 [2] 5e }

  condition:
    any of them
}