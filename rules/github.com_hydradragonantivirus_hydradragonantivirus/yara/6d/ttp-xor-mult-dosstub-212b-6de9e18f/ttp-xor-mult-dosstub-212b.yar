rule TTP_XOR_MULT_DOSStub_212b {
  strings:
    $key_212b = { 75 43 [2] 01 5b [2] 46 59 [2] 01 48 [2] 4f 44 [2] 43 4e [2] 54 45 [2] 4f 0b [2] 72 }

  condition:
    any of them
}