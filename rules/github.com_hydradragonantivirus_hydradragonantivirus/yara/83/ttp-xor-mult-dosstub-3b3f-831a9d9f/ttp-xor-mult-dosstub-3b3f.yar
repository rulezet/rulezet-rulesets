rule TTP_XOR_MULT_DOSStub_3b3f {
  strings:
    $key_3b3f = { 6f 57 [2] 1b 4f [2] 5c 4d [2] 1b 5c [2] 55 50 [2] 59 5a [2] 4e 51 [2] 55 1f [2] 68 }

  condition:
    any of them
}