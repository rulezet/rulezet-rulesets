rule TTP_XOR_MULT_DOSStub_6eef {
  strings:
    $key_6eef = { 3a 87 [2] 4e 9f [2] 09 9d [2] 4e 8c [2] 00 80 [2] 0c 8a [2] 1b 81 [2] 00 cf [2] 3d }

  condition:
    any of them
}