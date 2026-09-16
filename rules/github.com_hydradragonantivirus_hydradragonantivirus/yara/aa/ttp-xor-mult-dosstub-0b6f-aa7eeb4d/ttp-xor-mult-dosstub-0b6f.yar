rule TTP_XOR_MULT_DOSStub_0b6f {
  strings:
    $key_0b6f = { 5f 07 [2] 2b 1f [2] 6c 1d [2] 2b 0c [2] 65 00 [2] 69 0a [2] 7e 01 [2] 65 4f [2] 58 }

  condition:
    any of them
}