rule TTP_XOR_MULT_DOSStub_2f36 {
  strings:
    $key_2f36 = { 7b 5e [2] 0f 46 [2] 48 44 [2] 0f 55 [2] 41 59 [2] 4d 53 [2] 5a 58 [2] 41 16 [2] 7c }

  condition:
    any of them
}