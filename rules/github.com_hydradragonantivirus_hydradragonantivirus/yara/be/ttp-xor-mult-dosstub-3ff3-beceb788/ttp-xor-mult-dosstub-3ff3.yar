rule TTP_XOR_MULT_DOSStub_3ff3 {
  strings:
    $key_3ff3 = { 6b 9b [2] 1f 83 [2] 58 81 [2] 1f 90 [2] 51 9c [2] 5d 96 [2] 4a 9d [2] 51 d3 [2] 6c }

  condition:
    any of them
}