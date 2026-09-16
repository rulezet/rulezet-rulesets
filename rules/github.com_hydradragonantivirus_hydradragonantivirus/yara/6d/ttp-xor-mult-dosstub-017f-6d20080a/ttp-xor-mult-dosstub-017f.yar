rule TTP_XOR_MULT_DOSStub_017f {
  strings:
    $key_017f = { 55 17 [2] 21 0f [2] 66 0d [2] 21 1c [2] 6f 10 [2] 63 1a [2] 74 11 [2] 6f 5f [2] 52 }

  condition:
    any of them
}