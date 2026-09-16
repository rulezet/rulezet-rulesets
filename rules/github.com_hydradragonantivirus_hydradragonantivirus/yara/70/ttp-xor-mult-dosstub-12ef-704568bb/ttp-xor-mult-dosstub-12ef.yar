rule TTP_XOR_MULT_DOSStub_12ef {
  strings:
    $key_12ef = { 46 87 [2] 32 9f [2] 75 9d [2] 32 8c [2] 7c 80 [2] 70 8a [2] 67 81 [2] 7c cf [2] 41 }

  condition:
    any of them
}