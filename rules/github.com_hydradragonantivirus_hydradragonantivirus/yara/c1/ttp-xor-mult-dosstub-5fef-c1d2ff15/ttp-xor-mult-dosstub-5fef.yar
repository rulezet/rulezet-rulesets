rule TTP_XOR_MULT_DOSStub_5fef {
  strings:
    $key_5fef = { 0b 87 [2] 7f 9f [2] 38 9d [2] 7f 8c [2] 31 80 [2] 3d 8a [2] 2a 81 [2] 31 cf [2] 0c }

  condition:
    any of them
}