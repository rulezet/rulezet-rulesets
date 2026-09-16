rule TTP_XOR_MULT_DOSStub_3f6f {
  strings:
    $key_3f6f = { 6b 07 [2] 1f 1f [2] 58 1d [2] 1f 0c [2] 51 00 [2] 5d 0a [2] 4a 01 [2] 51 4f [2] 6c }

  condition:
    any of them
}