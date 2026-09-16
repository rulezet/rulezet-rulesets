rule TTP_XOR_MULT_DOSStub_6a6f {
  strings:
    $key_6a6f = { 3e 07 [2] 4a 1f [2] 0d 1d [2] 4a 0c [2] 04 00 [2] 08 0a [2] 1f 01 [2] 04 4f [2] 39 }

  condition:
    any of them
}