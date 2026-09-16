rule TTP_XOR_MULT_DOSStub_0964 {
  strings:
    $key_0964 = { 5d 0c [2] 29 14 [2] 6e 16 [2] 29 07 [2] 67 0b [2] 6b 01 [2] 7c 0a [2] 67 44 [2] 5a }

  condition:
    any of them
}