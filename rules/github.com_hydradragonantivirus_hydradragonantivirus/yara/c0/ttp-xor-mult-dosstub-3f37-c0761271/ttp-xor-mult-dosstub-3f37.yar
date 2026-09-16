rule TTP_XOR_MULT_DOSStub_3f37 {
  strings:
    $key_3f37 = { 6b 5f [2] 1f 47 [2] 58 45 [2] 1f 54 [2] 51 58 [2] 5d 52 [2] 4a 59 [2] 51 17 [2] 6c }

  condition:
    any of them
}