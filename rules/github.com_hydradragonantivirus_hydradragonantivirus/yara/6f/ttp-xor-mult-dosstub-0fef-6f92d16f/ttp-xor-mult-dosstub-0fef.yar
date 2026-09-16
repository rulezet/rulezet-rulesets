rule TTP_XOR_MULT_DOSStub_0fef {
  strings:
    $key_0fef = { 5b 87 [2] 2f 9f [2] 68 9d [2] 2f 8c [2] 61 80 [2] 6d 8a [2] 7a 81 [2] 61 cf [2] 5c }

  condition:
    any of them
}