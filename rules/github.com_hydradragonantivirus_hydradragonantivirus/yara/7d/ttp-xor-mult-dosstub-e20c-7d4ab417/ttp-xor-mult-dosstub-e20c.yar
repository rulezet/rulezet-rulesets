rule TTP_XOR_MULT_DOSStub_e20c {
  strings:
    $key_e20c = { b6 64 [2] c2 7c [2] 85 7e [2] c2 6f [2] 8c 63 [2] 80 69 [2] 97 62 [2] 8c 2c [2] b1 }

  condition:
    any of them
}