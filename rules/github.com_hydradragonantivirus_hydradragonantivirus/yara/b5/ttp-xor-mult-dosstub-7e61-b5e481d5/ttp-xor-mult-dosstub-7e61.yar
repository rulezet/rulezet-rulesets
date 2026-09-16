rule TTP_XOR_MULT_DOSStub_7e61 {
  strings:
    $key_7e61 = { 2a 09 [2] 5e 11 [2] 19 13 [2] 5e 02 [2] 10 0e [2] 1c 04 [2] 0b 0f [2] 10 41 [2] 2d }

  condition:
    any of them
}