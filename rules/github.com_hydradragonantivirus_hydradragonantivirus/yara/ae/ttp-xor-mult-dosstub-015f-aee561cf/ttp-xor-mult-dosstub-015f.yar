rule TTP_XOR_MULT_DOSStub_015f {
  strings:
    $key_015f = { 55 37 [2] 21 2f [2] 66 2d [2] 21 3c [2] 6f 30 [2] 63 3a [2] 74 31 [2] 6f 7f [2] 52 }

  condition:
    any of them
}