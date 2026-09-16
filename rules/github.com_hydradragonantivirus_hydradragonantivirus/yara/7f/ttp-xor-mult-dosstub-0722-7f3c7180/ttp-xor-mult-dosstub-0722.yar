rule TTP_XOR_MULT_DOSStub_0722 {
  strings:
    $key_0722 = { 53 4a [2] 27 52 [2] 60 50 [2] 27 41 [2] 69 4d [2] 65 47 [2] 72 4c [2] 69 02 [2] 54 }

  condition:
    any of them
}