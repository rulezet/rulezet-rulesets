rule TTP_XOR_MULT_DOSStub_501e {
  strings:
    $key_501e = { 04 76 [2] 70 6e [2] 37 6c [2] 70 7d [2] 3e 71 [2] 32 7b [2] 25 70 [2] 3e 3e [2] 03 }

  condition:
    any of them
}