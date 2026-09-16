rule TTP_XOR_MULT_DOSStub_ee2d {
  strings:
    $key_ee2d = { ba 45 [2] ce 5d [2] 89 5f [2] ce 4e [2] 80 42 [2] 8c 48 [2] 9b 43 [2] 80 0d [2] bd }

  condition:
    any of them
}