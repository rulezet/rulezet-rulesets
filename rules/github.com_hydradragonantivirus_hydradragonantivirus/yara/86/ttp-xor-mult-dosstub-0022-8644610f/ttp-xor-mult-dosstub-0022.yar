rule TTP_XOR_MULT_DOSStub_0022 {
  strings:
    $key_0022 = { 54 4a [2] 20 52 [2] 67 50 [2] 20 41 [2] 6e 4d [2] 62 47 [2] 75 4c [2] 6e 02 [2] 53 }

  condition:
    any of them
}