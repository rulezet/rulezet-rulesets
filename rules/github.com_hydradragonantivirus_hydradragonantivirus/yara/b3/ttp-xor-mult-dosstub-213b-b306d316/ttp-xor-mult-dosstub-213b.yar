rule TTP_XOR_MULT_DOSStub_213b {
  strings:
    $key_213b = { 75 53 [2] 01 4b [2] 46 49 [2] 01 58 [2] 4f 54 [2] 43 5e [2] 54 55 [2] 4f 1b [2] 72 }

  condition:
    any of them
}