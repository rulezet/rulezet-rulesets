rule TTP_XOR_MULT_DOSStub_660f {
  strings:
    $key_660f = { 32 67 [2] 46 7f [2] 01 7d [2] 46 6c [2] 08 60 [2] 04 6a [2] 13 61 [2] 08 2f [2] 35 }

  condition:
    any of them
}