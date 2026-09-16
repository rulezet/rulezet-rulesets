rule TTP_XOR_MULT_DOSStub_2b55 {
  strings:
    $key_2b55 = { 7f 3d [2] 0b 25 [2] 4c 27 [2] 0b 36 [2] 45 3a [2] 49 30 [2] 5e 3b [2] 45 75 [2] 78 }

  condition:
    any of them
}