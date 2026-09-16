rule TTP_XOR_MULT_DOSStub_2ff0 {
  strings:
    $key_2ff0 = { 7b 98 [2] 0f 80 [2] 48 82 [2] 0f 93 [2] 41 9f [2] 4d 95 [2] 5a 9e [2] 41 d0 [2] 7c }

  condition:
    any of them
}