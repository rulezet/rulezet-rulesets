rule TTP_XOR_MULT_DOSStub_61f4 {
  strings:
    $key_61f4 = { 35 9c [2] 41 84 [2] 06 86 [2] 41 97 [2] 0f 9b [2] 03 91 [2] 14 9a [2] 0f d4 [2] 32 }

  condition:
    any of them
}