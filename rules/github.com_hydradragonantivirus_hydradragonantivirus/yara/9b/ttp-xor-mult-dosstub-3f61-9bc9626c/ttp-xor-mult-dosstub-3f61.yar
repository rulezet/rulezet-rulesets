rule TTP_XOR_MULT_DOSStub_3f61 {
  strings:
    $key_3f61 = { 6b 09 [2] 1f 11 [2] 58 13 [2] 1f 02 [2] 51 0e [2] 5d 04 [2] 4a 0f [2] 51 41 [2] 6c }

  condition:
    any of them
}