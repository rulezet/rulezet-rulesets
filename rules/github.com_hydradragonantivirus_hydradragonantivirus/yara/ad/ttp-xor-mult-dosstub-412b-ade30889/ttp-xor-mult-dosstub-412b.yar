rule TTP_XOR_MULT_DOSStub_412b {
  strings:
    $key_412b = { 15 43 [2] 61 5b [2] 26 59 [2] 61 48 [2] 2f 44 [2] 23 4e [2] 34 45 [2] 2f 0b [2] 12 }

  condition:
    any of them
}