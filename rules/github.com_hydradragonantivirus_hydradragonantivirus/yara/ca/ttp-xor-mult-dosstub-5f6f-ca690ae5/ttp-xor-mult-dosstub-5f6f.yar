rule TTP_XOR_MULT_DOSStub_5f6f {
  strings:
    $key_5f6f = { 0b 07 [2] 7f 1f [2] 38 1d [2] 7f 0c [2] 31 00 [2] 3d 0a [2] 2a 01 [2] 31 4f [2] 0c }

  condition:
    any of them
}