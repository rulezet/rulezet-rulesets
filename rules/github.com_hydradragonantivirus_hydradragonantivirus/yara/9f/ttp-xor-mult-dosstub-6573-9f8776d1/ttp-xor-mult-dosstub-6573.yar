rule TTP_XOR_MULT_DOSStub_6573 {
  strings:
    $key_6573 = { 31 1b [2] 45 03 [2] 02 01 [2] 45 10 [2] 0b 1c [2] 07 16 [2] 10 1d [2] 0b 53 [2] 36 }

  condition:
    any of them
}