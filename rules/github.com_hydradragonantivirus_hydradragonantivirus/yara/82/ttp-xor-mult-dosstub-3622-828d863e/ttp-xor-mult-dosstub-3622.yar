rule TTP_XOR_MULT_DOSStub_3622 {
  strings:
    $key_3622 = { 62 4a [2] 16 52 [2] 51 50 [2] 16 41 [2] 58 4d [2] 54 47 [2] 43 4c [2] 58 02 [2] 65 }

  condition:
    any of them
}