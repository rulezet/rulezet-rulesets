rule TTP_XOR_MULT_DOSStub_302d {
  strings:
    $key_302d = { 64 45 [2] 10 5d [2] 57 5f [2] 10 4e [2] 5e 42 [2] 52 48 [2] 45 43 [2] 5e 0d [2] 63 }

  condition:
    any of them
}