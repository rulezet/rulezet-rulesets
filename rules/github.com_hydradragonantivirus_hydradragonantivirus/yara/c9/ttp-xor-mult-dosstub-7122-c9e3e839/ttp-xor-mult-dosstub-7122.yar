rule TTP_XOR_MULT_DOSStub_7122 {
  strings:
    $key_7122 = { 25 4a [2] 51 52 [2] 16 50 [2] 51 41 [2] 1f 4d [2] 13 47 [2] 04 4c [2] 1f 02 [2] 22 }

  condition:
    any of them
}