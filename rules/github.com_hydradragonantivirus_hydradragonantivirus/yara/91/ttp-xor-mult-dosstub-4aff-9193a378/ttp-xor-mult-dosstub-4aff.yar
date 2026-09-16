rule TTP_XOR_MULT_DOSStub_4aff {
  strings:
    $key_4aff = { 1e 97 [2] 6a 8f [2] 2d 8d [2] 6a 9c [2] 24 90 [2] 28 9a [2] 3f 91 [2] 24 df [2] 19 }

  condition:
    any of them
}