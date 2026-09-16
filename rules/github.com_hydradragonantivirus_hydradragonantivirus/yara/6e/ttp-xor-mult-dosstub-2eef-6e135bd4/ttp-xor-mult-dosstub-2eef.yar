rule TTP_XOR_MULT_DOSStub_2eef {
  strings:
    $key_2eef = { 7a 87 [2] 0e 9f [2] 49 9d [2] 0e 8c [2] 40 80 [2] 4c 8a [2] 5b 81 [2] 40 cf [2] 7d }

  condition:
    any of them
}