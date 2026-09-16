rule TTP_XOR_MULT_DOSStub_ee07 {
  strings:
    $key_ee07 = { ba 6f [2] ce 77 [2] 89 75 [2] ce 64 [2] 80 68 [2] 8c 62 [2] 9b 69 [2] 80 27 [2] bd }

  condition:
    any of them
}