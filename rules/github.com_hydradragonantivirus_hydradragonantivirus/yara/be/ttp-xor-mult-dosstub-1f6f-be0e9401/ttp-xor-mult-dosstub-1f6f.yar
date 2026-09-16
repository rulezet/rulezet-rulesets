rule TTP_XOR_MULT_DOSStub_1f6f {
  strings:
    $key_1f6f = { 4b 07 [2] 3f 1f [2] 78 1d [2] 3f 0c [2] 71 00 [2] 7d 0a [2] 6a 01 [2] 71 4f [2] 4c }

  condition:
    any of them
}