rule TTP_XOR_MULT_DOSStub_f567 {
  strings:
    $key_f567 = { a1 0f [2] d5 17 [2] 92 15 [2] d5 04 [2] 9b 08 [2] 97 02 [2] 80 09 [2] 9b 47 [2] a6 }

  condition:
    any of them
}