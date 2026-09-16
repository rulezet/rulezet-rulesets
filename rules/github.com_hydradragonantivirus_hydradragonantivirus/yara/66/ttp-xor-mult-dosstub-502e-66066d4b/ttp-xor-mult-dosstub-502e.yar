rule TTP_XOR_MULT_DOSStub_502e {
  strings:
    $key_502e = { 04 46 [2] 70 5e [2] 37 5c [2] 70 4d [2] 3e 41 [2] 32 4b [2] 25 40 [2] 3e 0e [2] 03 }

  condition:
    any of them
}