rule TTP_XOR_MULT_DOSStub_eea2 {
  strings:
    $key_eea2 = { ba ca [2] ce d2 [2] 89 d0 [2] ce c1 [2] 80 cd [2] 8c c7 [2] 9b cc [2] 80 82 [2] bd }

  condition:
    any of them
}