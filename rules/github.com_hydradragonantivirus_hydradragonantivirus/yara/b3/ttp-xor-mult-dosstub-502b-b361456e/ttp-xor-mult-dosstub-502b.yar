rule TTP_XOR_MULT_DOSStub_502b {
  strings:
    $key_502b = { 04 43 [2] 70 5b [2] 37 59 [2] 70 48 [2] 3e 44 [2] 32 4e [2] 25 45 [2] 3e 0b [2] 03 }

  condition:
    any of them
}