rule TTP_XOR_MULT_DOSStub_6b31 {
  strings:
    $key_6b31 = { 3f 59 [2] 4b 41 [2] 0c 43 [2] 4b 52 [2] 05 5e [2] 09 54 [2] 1e 5f [2] 05 11 [2] 38 }

  condition:
    any of them
}