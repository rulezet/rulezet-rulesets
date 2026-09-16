rule TTP_XOR_MULT_DOSStub_2800 {
  strings:
    $key_2800 = { 7c 68 [2] 08 70 [2] 4f 72 [2] 08 63 [2] 46 6f [2] 4a 65 [2] 5d 6e [2] 46 20 [2] 7b }

  condition:
    any of them
}