rule TTP_XOR_MULT_DOSStub_536f {
  strings:
    $key_536f = { 07 07 [2] 73 1f [2] 34 1d [2] 73 0c [2] 3d 00 [2] 31 0a [2] 26 01 [2] 3d 4f [2] 00 }

  condition:
    any of them
}