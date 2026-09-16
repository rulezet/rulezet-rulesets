rule TTP_XOR_MULT_DOSStub_196f {
  strings:
    $key_196f = { 4d 07 [2] 39 1f [2] 7e 1d [2] 39 0c [2] 77 00 [2] 7b 0a [2] 6c 01 [2] 77 4f [2] 4a }

  condition:
    any of them
}