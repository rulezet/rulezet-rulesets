rule TTP_XOR_MULT_DOSStub_4fef {
  strings:
    $key_4fef = { 1b 87 [2] 6f 9f [2] 28 9d [2] 6f 8c [2] 21 80 [2] 2d 8a [2] 3a 81 [2] 21 cf [2] 1c }

  condition:
    any of them
}