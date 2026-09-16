rule TTP_XOR_MULT_DOSStub_3ff0 {
  strings:
    $key_3ff0 = { 6b 98 [2] 1f 80 [2] 58 82 [2] 1f 93 [2] 51 9f [2] 5d 95 [2] 4a 9e [2] 51 d0 [2] 6c }

  condition:
    any of them
}