rule TTP_XOR_MULT_DOSStub_0e67 {
  strings:
    $key_0e67 = { 5a 0f [2] 2e 17 [2] 69 15 [2] 2e 04 [2] 60 08 [2] 6c 02 [2] 7b 09 [2] 60 47 [2] 5d }

  condition:
    any of them
}