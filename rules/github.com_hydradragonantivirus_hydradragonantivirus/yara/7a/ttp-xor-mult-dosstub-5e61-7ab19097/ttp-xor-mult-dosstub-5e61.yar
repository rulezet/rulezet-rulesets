rule TTP_XOR_MULT_DOSStub_5e61 {
  strings:
    $key_5e61 = { 0a 09 [2] 7e 11 [2] 39 13 [2] 7e 02 [2] 30 0e [2] 3c 04 [2] 2b 0f [2] 30 41 [2] 0d }

  condition:
    any of them
}