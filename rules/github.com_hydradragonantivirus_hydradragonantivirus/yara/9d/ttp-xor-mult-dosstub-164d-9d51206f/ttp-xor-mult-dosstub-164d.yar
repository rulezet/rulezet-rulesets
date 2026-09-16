rule TTP_XOR_MULT_DOSStub_164d {
  strings:
    $key_164d = { 42 25 [2] 36 3d [2] 71 3f [2] 36 2e [2] 78 22 [2] 74 28 [2] 63 23 [2] 78 6d [2] 45 }

  condition:
    any of them
}