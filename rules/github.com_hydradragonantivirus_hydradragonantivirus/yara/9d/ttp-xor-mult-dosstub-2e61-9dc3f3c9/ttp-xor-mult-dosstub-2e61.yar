rule TTP_XOR_MULT_DOSStub_2e61 {
  strings:
    $key_2e61 = { 7a 09 [2] 0e 11 [2] 49 13 [2] 0e 02 [2] 40 0e [2] 4c 04 [2] 5b 0f [2] 40 41 [2] 7d }

  condition:
    any of them
}