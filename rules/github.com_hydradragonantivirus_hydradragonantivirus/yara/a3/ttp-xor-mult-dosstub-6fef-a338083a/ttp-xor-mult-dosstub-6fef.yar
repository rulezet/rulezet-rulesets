rule TTP_XOR_MULT_DOSStub_6fef {
  strings:
    $key_6fef = { 3b 87 [2] 4f 9f [2] 08 9d [2] 4f 8c [2] 01 80 [2] 0d 8a [2] 1a 81 [2] 01 cf [2] 3c }

  condition:
    any of them
}