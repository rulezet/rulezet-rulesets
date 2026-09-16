rule TTP_XOR_MULT_DOSStub_655b {
  strings:
    $key_655b = { 31 33 [2] 45 2b [2] 02 29 [2] 45 38 [2] 0b 34 [2] 07 3e [2] 10 35 [2] 0b 7b [2] 36 }

  condition:
    any of them
}