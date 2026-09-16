rule TTP_XOR_MULT_DOSStub_1f5f {
  strings:
    $key_1f5f = { 4b 37 [2] 3f 2f [2] 78 2d [2] 3f 3c [2] 71 30 [2] 7d 3a [2] 6a 31 [2] 71 7f [2] 4c }

  condition:
    any of them
}