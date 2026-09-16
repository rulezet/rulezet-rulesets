rule TTP_XOR_MULT_DOSStub_666f {
  strings:
    $key_666f = { 32 07 [2] 46 1f [2] 01 1d [2] 46 0c [2] 08 00 [2] 04 0a [2] 13 01 [2] 08 4f [2] 35 }

  condition:
    any of them
}