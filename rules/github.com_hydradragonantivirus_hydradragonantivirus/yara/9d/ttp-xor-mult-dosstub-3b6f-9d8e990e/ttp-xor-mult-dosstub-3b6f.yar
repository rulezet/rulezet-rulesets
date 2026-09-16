rule TTP_XOR_MULT_DOSStub_3b6f {
  strings:
    $key_3b6f = { 6f 07 [2] 1b 1f [2] 5c 1d [2] 1b 0c [2] 55 00 [2] 59 0a [2] 4e 01 [2] 55 4f [2] 68 }

  condition:
    any of them
}