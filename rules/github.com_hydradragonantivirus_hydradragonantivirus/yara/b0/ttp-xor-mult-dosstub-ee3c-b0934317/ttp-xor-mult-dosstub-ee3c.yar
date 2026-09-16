rule TTP_XOR_MULT_DOSStub_ee3c {
  strings:
    $key_ee3c = { ba 54 [2] ce 4c [2] 89 4e [2] ce 5f [2] 80 53 [2] 8c 59 [2] 9b 52 [2] 80 1c [2] bd }

  condition:
    any of them
}