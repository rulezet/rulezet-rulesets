rule TTP_XOR_MULT_DOSStub_533e {
  strings:
    $key_533e = { 07 56 [2] 73 4e [2] 34 4c [2] 73 5d [2] 3d 51 [2] 31 5b [2] 26 50 [2] 3d 1e [2] 00 }

  condition:
    any of them
}