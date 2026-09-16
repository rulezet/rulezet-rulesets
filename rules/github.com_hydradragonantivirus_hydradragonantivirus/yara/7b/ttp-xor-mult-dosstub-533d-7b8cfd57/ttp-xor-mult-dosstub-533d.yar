rule TTP_XOR_MULT_DOSStub_533d {
  strings:
    $key_533d = { 07 55 [2] 73 4d [2] 34 4f [2] 73 5e [2] 3d 52 [2] 31 58 [2] 26 53 [2] 3d 1d [2] 00 }

  condition:
    any of them
}