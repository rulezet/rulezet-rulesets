rule TTP_XOR_MULT_DOSStub_58ef {
  strings:
    $key_58ef = { 0c 87 [2] 78 9f [2] 3f 9d [2] 78 8c [2] 36 80 [2] 3a 8a [2] 2d 81 [2] 36 cf [2] 0b }

  condition:
    any of them
}