rule TTP_XOR_MULT_DOSStub_02ef {
  strings:
    $key_02ef = { 56 87 [2] 22 9f [2] 65 9d [2] 22 8c [2] 6c 80 [2] 60 8a [2] 77 81 [2] 6c cf [2] 51 }

  condition:
    any of them
}