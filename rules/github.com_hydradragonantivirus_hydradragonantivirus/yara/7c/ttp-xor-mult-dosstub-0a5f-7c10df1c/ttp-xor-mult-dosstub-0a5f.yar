rule TTP_XOR_MULT_DOSStub_0a5f {
  strings:
    $key_0a5f = { 5e 37 [2] 2a 2f [2] 6d 2d [2] 2a 3c [2] 64 30 [2] 68 3a [2] 7f 31 [2] 64 7f [2] 59 }

  condition:
    any of them
}