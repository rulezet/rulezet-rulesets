rule TTP_XOR_MULT_DOSStub_502d {
  strings:
    $key_502d = { 04 45 [2] 70 5d [2] 37 5f [2] 70 4e [2] 3e 42 [2] 32 48 [2] 25 43 [2] 3e 0d [2] 03 }

  condition:
    any of them
}