rule TTP_XOR_MULT_DOSStub_7e67 {
  strings:
    $key_7e67 = { 2a 0f [2] 5e 17 [2] 19 15 [2] 5e 04 [2] 10 08 [2] 1c 02 [2] 0b 09 [2] 10 47 [2] 2d }

  condition:
    any of them
}