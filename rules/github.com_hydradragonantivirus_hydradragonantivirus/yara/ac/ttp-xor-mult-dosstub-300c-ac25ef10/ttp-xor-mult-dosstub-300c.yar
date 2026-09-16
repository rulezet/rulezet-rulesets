rule TTP_XOR_MULT_DOSStub_300c {
  strings:
    $key_300c = { 64 64 [2] 10 7c [2] 57 7e [2] 10 6f [2] 5e 63 [2] 52 69 [2] 45 62 [2] 5e 2c [2] 63 }

  condition:
    any of them
}