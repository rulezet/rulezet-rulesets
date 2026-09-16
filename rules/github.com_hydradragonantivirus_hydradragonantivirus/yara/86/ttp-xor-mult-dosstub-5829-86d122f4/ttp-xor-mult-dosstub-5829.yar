rule TTP_XOR_MULT_DOSStub_5829 {
  strings:
    $key_5829 = { 0c 41 [2] 78 59 [2] 3f 5b [2] 78 4a [2] 36 46 [2] 3a 4c [2] 2d 47 [2] 36 09 [2] 0b }

  condition:
    any of them
}