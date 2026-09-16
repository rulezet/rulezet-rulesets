rule TTP_XOR_MULT_DOSStub_3b5f {
  strings:
    $key_3b5f = { 6f 37 [2] 1b 2f [2] 5c 2d [2] 1b 3c [2] 55 30 [2] 59 3a [2] 4e 31 [2] 55 7f [2] 68 }

  condition:
    any of them
}