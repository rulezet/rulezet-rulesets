rule TTP_XOR_MULT_DOSStub_661e {
  strings:
    $key_661e = { 32 76 [2] 46 6e [2] 01 6c [2] 46 7d [2] 08 71 [2] 04 7b [2] 13 70 [2] 08 3e [2] 35 }

  condition:
    any of them
}