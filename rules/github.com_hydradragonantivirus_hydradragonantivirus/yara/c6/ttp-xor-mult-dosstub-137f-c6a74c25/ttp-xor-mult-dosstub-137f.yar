rule TTP_XOR_MULT_DOSStub_137f {
  strings:
    $key_137f = { 47 17 [2] 33 0f [2] 74 0d [2] 33 1c [2] 7d 10 [2] 71 1a [2] 66 11 [2] 7d 5f [2] 40 }

  condition:
    any of them
}