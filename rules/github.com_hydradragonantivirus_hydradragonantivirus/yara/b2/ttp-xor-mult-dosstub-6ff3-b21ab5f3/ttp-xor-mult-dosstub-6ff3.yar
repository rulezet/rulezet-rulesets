rule TTP_XOR_MULT_DOSStub_6ff3 {
  strings:
    $key_6ff3 = { 3b 9b [2] 4f 83 [2] 08 81 [2] 4f 90 [2] 01 9c [2] 0d 96 [2] 1a 9d [2] 01 d3 [2] 3c }

  condition:
    any of them
}