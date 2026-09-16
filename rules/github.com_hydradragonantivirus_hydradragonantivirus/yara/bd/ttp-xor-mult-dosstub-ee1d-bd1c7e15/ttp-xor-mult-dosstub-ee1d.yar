rule TTP_XOR_MULT_DOSStub_ee1d {
  strings:
    $key_ee1d = { ba 75 [2] ce 6d [2] 89 6f [2] ce 7e [2] 80 72 [2] 8c 78 [2] 9b 73 [2] 80 3d [2] bd }

  condition:
    any of them
}