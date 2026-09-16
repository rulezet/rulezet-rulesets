rule TTP_XOR_MULT_DOSStub_2f67 {
  strings:
    $key_2f67 = { 7b 0f [2] 0f 17 [2] 48 15 [2] 0f 04 [2] 41 08 [2] 4d 02 [2] 5a 09 [2] 41 47 [2] 7c }

  condition:
    any of them
}