rule TTP_XOR_MULT_DOSStub_386f {
  strings:
    $key_386f = { 6c 07 [2] 18 1f [2] 5f 1d [2] 18 0c [2] 56 00 [2] 5a 0a [2] 4d 01 [2] 56 4f [2] 6b }

  condition:
    any of them
}