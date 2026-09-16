rule TTP_XOR_MULT_DOSStub_3b7f {
  strings:
    $key_3b7f = { 6f 17 [2] 1b 0f [2] 5c 0d [2] 1b 1c [2] 55 10 [2] 59 1a [2] 4e 11 [2] 55 5f [2] 68 }

  condition:
    any of them
}