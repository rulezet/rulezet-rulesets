rule TTP_XOR_MULT_DOSStub_61f9 {
  strings:
    $key_61f9 = { 35 91 [2] 41 89 [2] 06 8b [2] 41 9a [2] 0f 96 [2] 03 9c [2] 14 97 [2] 0f d9 [2] 32 }

  condition:
    any of them
}