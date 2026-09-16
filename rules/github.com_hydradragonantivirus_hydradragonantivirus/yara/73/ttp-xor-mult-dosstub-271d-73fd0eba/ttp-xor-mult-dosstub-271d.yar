rule TTP_XOR_MULT_DOSStub_271d {
  strings:
    $key_271d = { 73 75 [2] 07 6d [2] 40 6f [2] 07 7e [2] 49 72 [2] 45 78 [2] 52 73 [2] 49 3d [2] 74 }

  condition:
    any of them
}