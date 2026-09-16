rule TTP_XOR_MULT_DOSStub_582f {
  strings:
    $key_582f = { 0c 47 [2] 78 5f [2] 3f 5d [2] 78 4c [2] 36 40 [2] 3a 4a [2] 2d 41 [2] 36 0f [2] 0b }

  condition:
    any of them
}