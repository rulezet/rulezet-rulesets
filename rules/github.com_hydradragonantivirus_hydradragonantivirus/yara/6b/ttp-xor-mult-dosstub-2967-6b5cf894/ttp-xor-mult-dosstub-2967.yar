rule TTP_XOR_MULT_DOSStub_2967 {
  strings:
    $key_2967 = { 7d 0f [2] 09 17 [2] 4e 15 [2] 09 04 [2] 47 08 [2] 4b 02 [2] 5c 09 [2] 47 47 [2] 7a }

  condition:
    any of them
}