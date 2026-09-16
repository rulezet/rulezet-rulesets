rule TTP_XOR_MULT_DOSStub_5f0c {
  strings:
    $key_5f0c = { 0b 64 [2] 7f 7c [2] 38 7e [2] 7f 6f [2] 31 63 [2] 3d 69 [2] 2a 62 [2] 31 2c [2] 0c }

  condition:
    any of them
}