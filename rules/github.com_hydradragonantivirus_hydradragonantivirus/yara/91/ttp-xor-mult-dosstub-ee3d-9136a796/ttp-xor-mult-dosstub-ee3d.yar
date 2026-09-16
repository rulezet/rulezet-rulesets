rule TTP_XOR_MULT_DOSStub_ee3d {
  strings:
    $key_ee3d = { ba 55 [2] ce 4d [2] 89 4f [2] ce 5e [2] 80 52 [2] 8c 58 [2] 9b 53 [2] 80 1d [2] bd }

  condition:
    any of them
}