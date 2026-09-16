rule TTP_XOR_MULT_DOSStub_0df9 {
  strings:
    $key_0df9 = { 59 91 [2] 2d 89 [2] 6a 8b [2] 2d 9a [2] 63 96 [2] 6f 9c [2] 78 97 [2] 63 d9 [2] 5e }

  condition:
    any of them
}