rule TTP_XOR_MULT_DOSStub_712b {
  strings:
    $key_712b = { 25 43 [2] 51 5b [2] 16 59 [2] 51 48 [2] 1f 44 [2] 13 4e [2] 04 45 [2] 1f 0b [2] 22 }

  condition:
    any of them
}