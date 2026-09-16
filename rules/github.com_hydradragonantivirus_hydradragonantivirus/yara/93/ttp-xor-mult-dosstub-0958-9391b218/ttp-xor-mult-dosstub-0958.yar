rule TTP_XOR_MULT_DOSStub_0958 {
  strings:
    $key_0958 = { 5d 30 [2] 29 28 [2] 6e 2a [2] 29 3b [2] 67 37 [2] 6b 3d [2] 7c 36 [2] 67 78 [2] 5a }

  condition:
    any of them
}