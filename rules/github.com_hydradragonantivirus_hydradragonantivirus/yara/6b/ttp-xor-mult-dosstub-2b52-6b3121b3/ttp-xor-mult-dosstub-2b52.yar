rule TTP_XOR_MULT_DOSStub_2b52 {
  strings:
    $key_2b52 = { 7f 3a [2] 0b 22 [2] 4c 20 [2] 0b 31 [2] 45 3d [2] 49 37 [2] 5e 3c [2] 45 72 [2] 78 }

  condition:
    any of them
}