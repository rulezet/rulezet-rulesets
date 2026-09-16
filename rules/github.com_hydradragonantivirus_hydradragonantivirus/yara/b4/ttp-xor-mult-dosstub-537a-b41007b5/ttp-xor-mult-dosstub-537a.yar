rule TTP_XOR_MULT_DOSStub_537a {
  strings:
    $key_537a = { 07 12 [2] 73 0a [2] 34 08 [2] 73 19 [2] 3d 15 [2] 31 1f [2] 26 14 [2] 3d 5a [2] 00 }

  condition:
    any of them
}