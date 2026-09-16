rule TTP_XOR_MULT_DOSStub_683f {
  strings:
    $key_683f = { 3c 57 [2] 48 4f [2] 0f 4d [2] 48 5c [2] 06 50 [2] 0a 5a [2] 1d 51 [2] 06 1f [2] 3b }

  condition:
    any of them
}