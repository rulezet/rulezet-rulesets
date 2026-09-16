rule TTP_XOR_MULT_DOSStub_532e {
  strings:
    $key_532e = { 07 46 [2] 73 5e [2] 34 5c [2] 73 4d [2] 3d 41 [2] 31 4b [2] 26 40 [2] 3d 0e [2] 00 }

  condition:
    any of them
}