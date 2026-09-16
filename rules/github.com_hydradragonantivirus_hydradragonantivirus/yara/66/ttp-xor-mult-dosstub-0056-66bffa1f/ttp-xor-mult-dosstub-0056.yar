rule TTP_XOR_MULT_DOSStub_0056 {
  strings:
    $key_0056 = { 54 3e [2] 20 26 [2] 67 24 [2] 20 35 [2] 6e 39 [2] 62 33 [2] 75 38 [2] 6e 76 [2] 53 }

  condition:
    any of them
}