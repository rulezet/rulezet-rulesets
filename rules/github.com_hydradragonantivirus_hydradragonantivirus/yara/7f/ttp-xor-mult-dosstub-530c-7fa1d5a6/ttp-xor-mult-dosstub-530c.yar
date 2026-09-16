rule TTP_XOR_MULT_DOSStub_530c {
  strings:
    $key_530c = { 07 64 [2] 73 7c [2] 34 7e [2] 73 6f [2] 3d 63 [2] 31 69 [2] 26 62 [2] 3d 2c [2] 00 }

  condition:
    any of them
}