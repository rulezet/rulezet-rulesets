rule TTP_XOR_MULT_DOSStub_6d5f {
  strings:
    $key_6d5f = { 39 37 [2] 4d 2f [2] 0a 2d [2] 4d 3c [2] 03 30 [2] 0f 3a [2] 18 31 [2] 03 7f [2] 3e }

  condition:
    any of them
}