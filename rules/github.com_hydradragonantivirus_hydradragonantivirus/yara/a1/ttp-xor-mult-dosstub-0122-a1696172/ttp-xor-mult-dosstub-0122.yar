rule TTP_XOR_MULT_DOSStub_0122 {
  strings:
    $key_0122 = { 55 4a [2] 21 52 [2] 66 50 [2] 21 41 [2] 6f 4d [2] 63 47 [2] 74 4c [2] 6f 02 [2] 52 }

  condition:
    any of them
}