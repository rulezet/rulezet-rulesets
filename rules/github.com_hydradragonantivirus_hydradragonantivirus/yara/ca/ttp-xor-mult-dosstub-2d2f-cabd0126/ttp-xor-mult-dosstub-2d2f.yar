rule TTP_XOR_MULT_DOSStub_2d2f {
  strings:
    $key_2d2f = { 79 47 [2] 0d 5f [2] 4a 5d [2] 0d 4c [2] 43 40 [2] 4f 4a [2] 58 41 [2] 43 0f [2] 7e }

  condition:
    any of them
}