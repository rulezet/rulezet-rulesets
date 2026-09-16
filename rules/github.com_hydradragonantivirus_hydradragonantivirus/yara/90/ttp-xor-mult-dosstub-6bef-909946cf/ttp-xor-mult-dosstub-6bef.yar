rule TTP_XOR_MULT_DOSStub_6bef {
  strings:
    $key_6bef = { 3f 87 [2] 4b 9f [2] 0c 9d [2] 4b 8c [2] 05 80 [2] 09 8a [2] 1e 81 [2] 05 cf [2] 38 }

  condition:
    any of them
}