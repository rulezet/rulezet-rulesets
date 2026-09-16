rule TTP_XOR_MULT_DOSStub_0708 {
  strings:
    $key_0708 = { 53 60 [2] 27 78 [2] 60 7a [2] 27 6b [2] 69 67 [2] 65 6d [2] 72 66 [2] 69 28 [2] 54 }

  condition:
    any of them
}