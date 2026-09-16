rule TTP_XOR_MULT_DOSStub_0a2e {
  strings:
    $key_0a2e = { 5e 46 [2] 2a 5e [2] 6d 5c [2] 2a 4d [2] 64 41 [2] 68 4b [2] 7f 40 [2] 64 0e [2] 59 }

  condition:
    any of them
}