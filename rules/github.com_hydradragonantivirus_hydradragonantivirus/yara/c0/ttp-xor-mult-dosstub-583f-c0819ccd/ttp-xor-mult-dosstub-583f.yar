rule TTP_XOR_MULT_DOSStub_583f {
  strings:
    $key_583f = { 0c 57 [2] 78 4f [2] 3f 4d [2] 78 5c [2] 36 50 [2] 3a 5a [2] 2d 51 [2] 36 1f [2] 0b }

  condition:
    any of them
}