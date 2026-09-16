rule TTP_XOR_MULT_DOSStub_012f {
  strings:
    $key_012f = { 55 47 [2] 21 5f [2] 66 5d [2] 21 4c [2] 6f 40 [2] 63 4a [2] 74 41 [2] 6f 0f [2] 52 }

  condition:
    any of them
}