rule TTP_XOR_MULT_DOSStub_2941 {
  strings:
    $key_2941 = { 7d 29 [2] 09 31 [2] 4e 33 [2] 09 22 [2] 47 2e [2] 4b 24 [2] 5c 2f [2] 47 61 [2] 7a }

  condition:
    any of them
}