rule TTP_XOR_MULT_DOSStub_6f6f {
  strings:
    $key_6f6f = { 3b 07 [2] 4f 1f [2] 08 1d [2] 4f 0c [2] 01 00 [2] 0d 0a [2] 1a 01 [2] 01 4f [2] 3c }

  condition:
    any of them
}