rule TTP_XOR_MULT_DOSStub_3e67 {
  strings:
    $key_3e67 = { 6a 0f [2] 1e 17 [2] 59 15 [2] 1e 04 [2] 50 08 [2] 5c 02 [2] 4b 09 [2] 50 47 [2] 6d }

  condition:
    any of them
}