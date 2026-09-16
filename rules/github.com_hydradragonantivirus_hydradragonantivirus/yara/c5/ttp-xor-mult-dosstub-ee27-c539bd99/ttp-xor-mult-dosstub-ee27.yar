rule TTP_XOR_MULT_DOSStub_ee27 {
  strings:
    $key_ee27 = { ba 4f [2] ce 57 [2] 89 55 [2] ce 44 [2] 80 48 [2] 8c 42 [2] 9b 49 [2] 80 07 [2] bd }

  condition:
    any of them
}