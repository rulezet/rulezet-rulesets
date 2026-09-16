rule TTP_XOR_MULT_DOSStub_ee29 {
  strings:
    $key_ee29 = { ba 41 [2] ce 59 [2] 89 5b [2] ce 4a [2] 80 46 [2] 8c 4c [2] 9b 47 [2] 80 09 [2] bd }

  condition:
    any of them
}