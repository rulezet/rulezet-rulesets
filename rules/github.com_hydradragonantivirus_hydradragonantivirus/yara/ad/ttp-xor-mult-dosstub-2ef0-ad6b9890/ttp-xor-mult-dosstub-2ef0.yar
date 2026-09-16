rule TTP_XOR_MULT_DOSStub_2ef0 {
  strings:
    $key_2ef0 = { 7a 98 [2] 0e 80 [2] 49 82 [2] 0e 93 [2] 40 9f [2] 4c 95 [2] 5b 9e [2] 40 d0 [2] 7d }

  condition:
    any of them
}