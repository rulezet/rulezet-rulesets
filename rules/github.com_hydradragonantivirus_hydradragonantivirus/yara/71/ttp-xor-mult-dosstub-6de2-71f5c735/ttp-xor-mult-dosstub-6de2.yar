rule TTP_XOR_MULT_DOSStub_6de2 {
  strings:
    $key_6de2 = { 39 8a [2] 4d 92 [2] 0a 90 [2] 4d 81 [2] 03 8d [2] 0f 87 [2] 18 8c [2] 03 c2 [2] 3e }

  condition:
    any of them
}