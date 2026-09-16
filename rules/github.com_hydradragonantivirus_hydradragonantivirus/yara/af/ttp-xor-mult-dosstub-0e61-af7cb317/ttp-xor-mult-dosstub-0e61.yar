rule TTP_XOR_MULT_DOSStub_0e61 {
  strings:
    $key_0e61 = { 5a 09 [2] 2e 11 [2] 69 13 [2] 2e 02 [2] 60 0e [2] 6c 04 [2] 7b 0f [2] 60 41 [2] 5d }

  condition:
    any of them
}