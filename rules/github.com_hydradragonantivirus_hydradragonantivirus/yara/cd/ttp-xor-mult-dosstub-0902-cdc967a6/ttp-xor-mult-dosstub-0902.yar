rule TTP_XOR_MULT_DOSStub_0902 {
  strings:
    $key_0902 = { 5d 6a [2] 29 72 [2] 6e 70 [2] 29 61 [2] 67 6d [2] 6b 67 [2] 7c 6c [2] 67 22 [2] 5a }

  condition:
    any of them
}