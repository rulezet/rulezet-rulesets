rule TTP_XOR_MULT_DOSStub_3b52 {
  strings:
    $key_3b52 = { 6f 3a [2] 1b 22 [2] 5c 20 [2] 1b 31 [2] 55 3d [2] 59 37 [2] 4e 3c [2] 55 72 [2] 68 }

  condition:
    any of them
}