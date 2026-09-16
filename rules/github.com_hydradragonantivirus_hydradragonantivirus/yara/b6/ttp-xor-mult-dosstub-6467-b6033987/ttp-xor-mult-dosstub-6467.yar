rule TTP_XOR_MULT_DOSStub_6467 {
  strings:
    $key_6467 = { 30 0f [2] 44 17 [2] 03 15 [2] 44 04 [2] 0a 08 [2] 06 02 [2] 11 09 [2] 0a 47 [2] 37 }

  condition:
    any of them
}