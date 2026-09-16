rule TTP_XOR_MULT_DOSStub_38f3 {
  strings:
    $key_38f3 = { 6c 9b [2] 18 83 [2] 5f 81 [2] 18 90 [2] 56 9c [2] 5a 96 [2] 4d 9d [2] 56 d3 [2] 6b }

  condition:
    any of them
}