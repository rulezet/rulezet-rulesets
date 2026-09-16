rule TTP_XOR_MULT_DOSStub_476f {
  strings:
    $key_476f = { 13 07 [2] 67 1f [2] 20 1d [2] 67 0c [2] 29 00 [2] 25 0a [2] 32 01 [2] 29 4f [2] 14 }

  condition:
    any of them
}