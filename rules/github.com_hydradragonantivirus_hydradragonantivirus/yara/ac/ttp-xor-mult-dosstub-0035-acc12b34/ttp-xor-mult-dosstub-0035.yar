rule TTP_XOR_MULT_DOSStub_0035 {
  strings:
    $key_0035 = { 54 5d [2] 20 45 [2] 67 47 [2] 20 56 [2] 6e 5a [2] 62 50 [2] 75 5b [2] 6e 15 [2] 53 }

  condition:
    any of them
}