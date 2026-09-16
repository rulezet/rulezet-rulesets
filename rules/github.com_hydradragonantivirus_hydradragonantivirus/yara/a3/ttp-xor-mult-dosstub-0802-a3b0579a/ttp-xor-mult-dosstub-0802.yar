rule TTP_XOR_MULT_DOSStub_0802 {
  strings:
    $key_0802 = { 5c 6a [2] 28 72 [2] 6f 70 [2] 28 61 [2] 66 6d [2] 6a 67 [2] 7d 6c [2] 66 22 [2] 5b }

  condition:
    any of them
}