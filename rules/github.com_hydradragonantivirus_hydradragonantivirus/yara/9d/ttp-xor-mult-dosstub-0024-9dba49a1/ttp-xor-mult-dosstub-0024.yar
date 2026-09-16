rule TTP_XOR_MULT_DOSStub_0024 {
  strings:
    $key_0024 = { 54 4c [2] 20 54 [2] 67 56 [2] 20 47 [2] 6e 4b [2] 62 41 [2] 75 4a [2] 6e 04 [2] 53 }

  condition:
    any of them
}