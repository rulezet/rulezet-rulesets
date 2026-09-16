rule TTP_XOR_MULT_DOSStub_681f {
  strings:
    $key_681f = { 3c 77 [2] 48 6f [2] 0f 6d [2] 48 7c [2] 06 70 [2] 0a 7a [2] 1d 71 [2] 06 3f [2] 3b }

  condition:
    any of them
}