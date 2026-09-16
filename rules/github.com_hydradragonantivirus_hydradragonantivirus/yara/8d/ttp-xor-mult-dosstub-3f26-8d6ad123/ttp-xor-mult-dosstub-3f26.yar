rule TTP_XOR_MULT_DOSStub_3f26 {
  strings:
    $key_3f26 = { 6b 4e [2] 1f 56 [2] 58 54 [2] 1f 45 [2] 51 49 [2] 5d 43 [2] 4a 48 [2] 51 06 [2] 6c }

  condition:
    any of them
}