rule TTP_XOR_MULT_DOSStub_6121 {
  strings:
    $key_6121 = { 35 49 [2] 41 51 [2] 06 53 [2] 41 42 [2] 0f 4e [2] 03 44 [2] 14 4f [2] 0f 01 [2] 32 }

  condition:
    any of them
}