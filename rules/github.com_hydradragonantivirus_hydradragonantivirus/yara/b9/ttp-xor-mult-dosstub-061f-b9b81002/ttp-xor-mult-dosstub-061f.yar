rule TTP_XOR_MULT_DOSStub_061f {
  strings:
    $key_061f = { 52 77 [2] 26 6f [2] 61 6d [2] 26 7c [2] 68 70 [2] 64 7a [2] 73 71 [2] 68 3f [2] 55 }

  condition:
    any of them
}