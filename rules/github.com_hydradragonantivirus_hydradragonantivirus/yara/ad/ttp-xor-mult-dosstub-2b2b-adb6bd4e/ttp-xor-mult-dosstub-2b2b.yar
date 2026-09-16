rule TTP_XOR_MULT_DOSStub_2b2b {
  strings:
    $key_2b2b = { 7f 43 [2] 0b 5b [2] 4c 59 [2] 0b 48 [2] 45 44 [2] 49 4e [2] 5e 45 [2] 45 0b [2] 78 }

  condition:
    any of them
}