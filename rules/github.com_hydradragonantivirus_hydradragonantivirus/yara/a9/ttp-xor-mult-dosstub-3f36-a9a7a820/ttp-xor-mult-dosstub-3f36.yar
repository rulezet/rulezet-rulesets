rule TTP_XOR_MULT_DOSStub_3f36 {
  strings:
    $key_3f36 = { 6b 5e [2] 1f 46 [2] 58 44 [2] 1f 55 [2] 51 59 [2] 5d 53 [2] 4a 58 [2] 51 16 [2] 6c }

  condition:
    any of them
}