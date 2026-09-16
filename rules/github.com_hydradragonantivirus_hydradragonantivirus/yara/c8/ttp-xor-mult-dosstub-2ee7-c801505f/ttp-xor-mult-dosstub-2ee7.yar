rule TTP_XOR_MULT_DOSStub_2ee7 {
  strings:
    $key_2ee7 = { 7a 8f [2] 0e 97 [2] 49 95 [2] 0e 84 [2] 40 88 [2] 4c 82 [2] 5b 89 [2] 40 c7 [2] 7d }

  condition:
    any of them
}