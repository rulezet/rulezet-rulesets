rule TTP_XOR_MULT_DOSStub_2911 {
  strings:
    $key_2911 = { 7d 79 [2] 09 61 [2] 4e 63 [2] 09 72 [2] 47 7e [2] 4b 74 [2] 5c 7f [2] 47 31 [2] 7a }

  condition:
    any of them
}