rule TTP_XOR_MULT_DOSStub_5e67 {
  strings:
    $key_5e67 = { 0a 0f [2] 7e 17 [2] 39 15 [2] 7e 04 [2] 30 08 [2] 3c 02 [2] 2b 09 [2] 30 47 [2] 0d }

  condition:
    any of them
}