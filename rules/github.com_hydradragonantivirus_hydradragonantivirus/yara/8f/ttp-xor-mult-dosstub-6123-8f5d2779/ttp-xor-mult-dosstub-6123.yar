rule TTP_XOR_MULT_DOSStub_6123 {
  strings:
    $key_6123 = { 35 4b [2] 41 53 [2] 06 51 [2] 41 40 [2] 0f 4c [2] 03 46 [2] 14 4d [2] 0f 03 [2] 32 }

  condition:
    any of them
}