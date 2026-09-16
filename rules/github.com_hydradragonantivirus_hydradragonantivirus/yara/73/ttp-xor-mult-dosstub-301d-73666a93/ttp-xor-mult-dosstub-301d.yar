rule TTP_XOR_MULT_DOSStub_301d {
  strings:
    $key_301d = { 64 75 [2] 10 6d [2] 57 6f [2] 10 7e [2] 5e 72 [2] 52 78 [2] 45 73 [2] 5e 3d [2] 63 }

  condition:
    any of them
}