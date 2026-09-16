rule TTP_XOR_MULT_DOSStub_6129 {
  strings:
    $key_6129 = { 35 41 [2] 41 59 [2] 06 5b [2] 41 4a [2] 0f 46 [2] 03 4c [2] 14 47 [2] 0f 09 [2] 32 }

  condition:
    any of them
}