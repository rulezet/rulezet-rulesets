rule TTP_XOR_MULT_DOSStub_212d {
  strings:
    $key_212d = { 75 45 [2] 01 5d [2] 46 5f [2] 01 4e [2] 4f 42 [2] 43 48 [2] 54 43 [2] 4f 0d [2] 72 }

  condition:
    any of them
}