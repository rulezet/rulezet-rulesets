rule TTP_XOR_MULT_DOSStub_626f {
  strings:
    $key_626f = { 36 07 [2] 42 1f [2] 05 1d [2] 42 0c [2] 0c 00 [2] 00 0a [2] 17 01 [2] 0c 4f [2] 31 }

  condition:
    any of them
}