rule TTP_XOR_MULT_DOSStub_1eef {
  strings:
    $key_1eef = { 4a 87 [2] 3e 9f [2] 79 9d [2] 3e 8c [2] 70 80 [2] 7c 8a [2] 6b 81 [2] 70 cf [2] 4d }

  condition:
    any of them
}