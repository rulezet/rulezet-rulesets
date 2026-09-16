rule TTP_XOR_MULT_DOSStub_6a22 {
  strings:
    $key_6a22 = { 3e 4a [2] 4a 52 [2] 0d 50 [2] 4a 41 [2] 04 4d [2] 08 47 [2] 1f 4c [2] 04 02 [2] 39 }

  condition:
    any of them
}