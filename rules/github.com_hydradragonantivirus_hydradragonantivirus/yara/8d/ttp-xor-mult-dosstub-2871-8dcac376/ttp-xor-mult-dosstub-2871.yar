rule TTP_XOR_MULT_DOSStub_2871 {
  strings:
    $key_2871 = { 7c 19 [2] 08 01 [2] 4f 03 [2] 08 12 [2] 46 1e [2] 4a 14 [2] 5d 1f [2] 46 51 [2] 7b }

  condition:
    any of them
}