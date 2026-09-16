rule TTP_XOR_MULT_DOSStub_6d21 {
  strings:
    $key_6d21 = { 39 49 [2] 4d 51 [2] 0a 53 [2] 4d 42 [2] 03 4e [2] 0f 44 [2] 18 4f [2] 03 01 [2] 3e }

  condition:
    any of them
}