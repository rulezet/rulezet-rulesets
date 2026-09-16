rule TTP_XOR_MULT_DOSStub_6de9 {
  strings:
    $key_6de9 = { 39 81 [2] 4d 99 [2] 0a 9b [2] 4d 8a [2] 03 86 [2] 0f 8c [2] 18 87 [2] 03 c9 [2] 3e }

  condition:
    any of them
}