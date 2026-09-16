rule TTP_XOR_MULT_DOSStub_ee23 {
  strings:
    $key_ee23 = { ba 4b [2] ce 53 [2] 89 51 [2] ce 40 [2] 80 4c [2] 8c 46 [2] 9b 4d [2] 80 03 [2] bd }

  condition:
    any of them
}