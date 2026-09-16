rule TTP_XOR_MULT_DOSStub_2f60 {
  strings:
    $key_2f60 = { 7b 08 [2] 0f 10 [2] 48 12 [2] 0f 03 [2] 41 0f [2] 4d 05 [2] 5a 0e [2] 41 40 [2] 7c }

  condition:
    any of them
}