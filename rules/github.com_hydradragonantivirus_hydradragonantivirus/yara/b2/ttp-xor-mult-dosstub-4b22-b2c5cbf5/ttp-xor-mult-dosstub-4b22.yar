rule TTP_XOR_MULT_DOSStub_4b22 {
  strings:
    $key_4b22 = { 1f 4a [2] 6b 52 [2] 2c 50 [2] 6b 41 [2] 25 4d [2] 29 47 [2] 3e 4c [2] 25 02 [2] 18 }

  condition:
    any of them
}