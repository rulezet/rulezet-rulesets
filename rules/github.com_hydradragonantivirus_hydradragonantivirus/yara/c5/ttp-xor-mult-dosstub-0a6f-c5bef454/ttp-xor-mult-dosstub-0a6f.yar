rule TTP_XOR_MULT_DOSStub_0a6f {
  strings:
    $key_0a6f = { 5e 07 [2] 2a 1f [2] 6d 1d [2] 2a 0c [2] 64 00 [2] 68 0a [2] 7f 01 [2] 64 4f [2] 59 }

  condition:
    any of them
}