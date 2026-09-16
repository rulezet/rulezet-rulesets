rule TTP_XOR_MULT_DOSStub_7bef {
  strings:
    $key_7bef = { 2f 87 [2] 5b 9f [2] 1c 9d [2] 5b 8c [2] 15 80 [2] 19 8a [2] 0e 81 [2] 15 cf [2] 28 }

  condition:
    any of them
}