rule TTP_XOR_MULT_DOSStub_3b58 {
  strings:
    $key_3b58 = { 6f 30 [2] 1b 28 [2] 5c 2a [2] 1b 3b [2] 55 37 [2] 59 3d [2] 4e 36 [2] 55 78 [2] 68 }

  condition:
    any of them
}