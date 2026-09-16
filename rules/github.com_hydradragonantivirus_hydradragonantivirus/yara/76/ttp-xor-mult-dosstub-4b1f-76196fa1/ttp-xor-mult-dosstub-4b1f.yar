rule TTP_XOR_MULT_DOSStub_4b1f {
  strings:
    $key_4b1f = { 1f 77 [2] 6b 6f [2] 2c 6d [2] 6b 7c [2] 25 70 [2] 29 7a [2] 3e 71 [2] 25 3f [2] 18 }

  condition:
    any of them
}