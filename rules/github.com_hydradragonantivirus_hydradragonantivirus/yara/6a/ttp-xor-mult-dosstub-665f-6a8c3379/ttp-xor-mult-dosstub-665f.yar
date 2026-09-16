rule TTP_XOR_MULT_DOSStub_665f {
  strings:
    $key_665f = { 32 37 [2] 46 2f [2] 01 2d [2] 46 3c [2] 08 30 [2] 04 3a [2] 13 31 [2] 08 7f [2] 35 }

  condition:
    any of them
}