rule TTP_XOR_MULT_DOSStub_6513 {
  strings:
    $key_6513 = { 31 7b [2] 45 63 [2] 02 61 [2] 45 70 [2] 0b 7c [2] 07 76 [2] 10 7d [2] 0b 33 [2] 36 }

  condition:
    any of them
}