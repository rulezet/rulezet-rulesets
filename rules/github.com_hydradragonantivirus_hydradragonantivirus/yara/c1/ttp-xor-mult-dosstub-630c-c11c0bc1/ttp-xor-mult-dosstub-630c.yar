rule TTP_XOR_MULT_DOSStub_630c {
  strings:
    $key_630c = { 37 64 [2] 43 7c [2] 04 7e [2] 43 6f [2] 0d 63 [2] 01 69 [2] 16 62 [2] 0d 2c [2] 30 }

  condition:
    any of them
}