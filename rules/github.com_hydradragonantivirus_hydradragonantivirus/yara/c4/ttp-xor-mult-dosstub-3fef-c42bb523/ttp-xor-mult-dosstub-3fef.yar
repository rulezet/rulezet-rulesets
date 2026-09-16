rule TTP_XOR_MULT_DOSStub_3fef {
  strings:
    $key_3fef = { 6b 87 [2] 1f 9f [2] 58 9d [2] 1f 8c [2] 51 80 [2] 5d 8a [2] 4a 81 [2] 51 cf [2] 6c }

  condition:
    any of them
}