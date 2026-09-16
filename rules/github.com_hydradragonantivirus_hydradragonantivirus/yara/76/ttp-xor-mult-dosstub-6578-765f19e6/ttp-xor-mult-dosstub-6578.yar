rule TTP_XOR_MULT_DOSStub_6578 {
  strings:
    $key_6578 = { 31 10 [2] 45 08 [2] 02 0a [2] 45 1b [2] 0b 17 [2] 07 1d [2] 10 16 [2] 0b 58 [2] 36 }

  condition:
    any of them
}