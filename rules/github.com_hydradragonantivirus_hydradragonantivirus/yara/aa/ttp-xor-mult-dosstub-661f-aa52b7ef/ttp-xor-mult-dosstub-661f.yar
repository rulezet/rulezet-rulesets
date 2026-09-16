rule TTP_XOR_MULT_DOSStub_661f {
  strings:
    $key_661f = { 32 77 [2] 46 6f [2] 01 6d [2] 46 7c [2] 08 70 [2] 04 7a [2] 13 71 [2] 08 3f [2] 35 }

  condition:
    any of them
}