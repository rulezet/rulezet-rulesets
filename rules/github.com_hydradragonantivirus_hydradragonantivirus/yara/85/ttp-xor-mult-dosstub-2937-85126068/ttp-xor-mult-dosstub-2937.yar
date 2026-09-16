rule TTP_XOR_MULT_DOSStub_2937 {
  strings:
    $key_2937 = { 7d 5f [2] 09 47 [2] 4e 45 [2] 09 54 [2] 47 58 [2] 4b 52 [2] 5c 59 [2] 47 17 [2] 7a }

  condition:
    any of them
}