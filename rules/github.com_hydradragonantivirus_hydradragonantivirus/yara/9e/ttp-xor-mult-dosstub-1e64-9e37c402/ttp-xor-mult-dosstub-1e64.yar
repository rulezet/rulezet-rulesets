rule TTP_XOR_MULT_DOSStub_1e64 {
  strings:
    $key_1e64 = { 4a 0c [2] 3e 14 [2] 79 16 [2] 3e 07 [2] 70 0b [2] 7c 01 [2] 6b 0a [2] 70 44 [2] 4d }

  condition:
    any of them
}