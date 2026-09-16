rule TTP_XOR_MULT_DOSStub_335f {
  strings:
    $key_335f = { 67 37 [2] 13 2f [2] 54 2d [2] 13 3c [2] 5d 30 [2] 51 3a [2] 46 31 [2] 5d 7f [2] 60 }

  condition:
    any of them
}