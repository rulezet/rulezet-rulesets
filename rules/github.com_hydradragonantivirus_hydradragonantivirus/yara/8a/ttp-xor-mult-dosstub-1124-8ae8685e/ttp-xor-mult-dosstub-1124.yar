rule TTP_XOR_MULT_DOSStub_1124 {
  strings:
    $key_1124 = { 45 4c [2] 31 54 [2] 76 56 [2] 31 47 [2] 7f 4b [2] 73 41 [2] 64 4a [2] 7f 04 [2] 42 }

  condition:
    any of them
}