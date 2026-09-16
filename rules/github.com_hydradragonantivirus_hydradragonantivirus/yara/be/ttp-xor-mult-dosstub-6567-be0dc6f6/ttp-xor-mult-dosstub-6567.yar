rule TTP_XOR_MULT_DOSStub_6567 {
  strings:
    $key_6567 = { 31 0f [2] 45 17 [2] 02 15 [2] 45 04 [2] 0b 08 [2] 07 02 [2] 10 09 [2] 0b 47 [2] 36 }

  condition:
    any of them
}