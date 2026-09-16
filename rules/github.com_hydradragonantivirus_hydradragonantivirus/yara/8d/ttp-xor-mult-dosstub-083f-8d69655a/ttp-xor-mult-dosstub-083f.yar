rule TTP_XOR_MULT_DOSStub_083f {
  strings:
    $key_083f = { 5c 57 [2] 28 4f [2] 6f 4d [2] 28 5c [2] 66 50 [2] 6a 5a [2] 7d 51 [2] 66 1f [2] 5b }

  condition:
    any of them
}