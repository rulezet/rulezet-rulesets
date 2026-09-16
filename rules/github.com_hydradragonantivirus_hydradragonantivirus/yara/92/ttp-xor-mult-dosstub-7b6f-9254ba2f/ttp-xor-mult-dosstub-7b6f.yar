rule TTP_XOR_MULT_DOSStub_7b6f {
  strings:
    $key_7b6f = { 2f 07 [2] 5b 1f [2] 1c 1d [2] 5b 0c [2] 15 00 [2] 19 0a [2] 0e 01 [2] 15 4f [2] 28 }

  condition:
    any of them
}