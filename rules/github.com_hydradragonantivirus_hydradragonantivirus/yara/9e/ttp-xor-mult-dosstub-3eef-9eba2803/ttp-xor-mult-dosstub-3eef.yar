rule TTP_XOR_MULT_DOSStub_3eef {
  strings:
    $key_3eef = { 6a 87 [2] 1e 9f [2] 59 9d [2] 1e 8c [2] 50 80 [2] 5c 8a [2] 4b 81 [2] 50 cf [2] 6d }

  condition:
    any of them
}