rule TTP_XOR_MULT_DOSStub_286f {
  strings:
    $key_286f = { 7c 07 [2] 08 1f [2] 4f 1d [2] 08 0c [2] 46 00 [2] 4a 0a [2] 5d 01 [2] 46 4f [2] 7b }

  condition:
    any of them
}