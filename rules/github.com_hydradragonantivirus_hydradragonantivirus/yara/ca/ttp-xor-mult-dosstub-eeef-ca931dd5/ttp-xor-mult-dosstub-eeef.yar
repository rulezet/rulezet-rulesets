rule TTP_XOR_MULT_DOSStub_eeef {
  strings:
    $key_eeef = { ba 87 [2] ce 9f [2] 89 9d [2] ce 8c [2] 80 80 [2] 8c 8a [2] 9b 81 [2] 80 cf [2] bd }

  condition:
    any of them
}