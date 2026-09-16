rule TTP_XOR_MULT_DOSStub_72ef {
  strings:
    $key_72ef = { 26 87 [2] 52 9f [2] 15 9d [2] 52 8c [2] 1c 80 [2] 10 8a [2] 07 81 [2] 1c cf [2] 21 }

  condition:
    any of them
}