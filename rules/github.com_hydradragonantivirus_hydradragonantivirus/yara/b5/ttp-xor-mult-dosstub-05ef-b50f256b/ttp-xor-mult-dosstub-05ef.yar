rule TTP_XOR_MULT_DOSStub_05ef {
  strings:
    $key_05ef = { 51 87 [2] 25 9f [2] 62 9d [2] 25 8c [2] 6b 80 [2] 67 8a [2] 70 81 [2] 6b cf [2] 56 }

  condition:
    any of them
}