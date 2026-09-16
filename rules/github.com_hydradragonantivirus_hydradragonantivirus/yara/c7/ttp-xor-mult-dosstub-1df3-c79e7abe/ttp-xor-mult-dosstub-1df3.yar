rule TTP_XOR_MULT_DOSStub_1df3 {
  strings:
    $key_1df3 = { 49 9b [2] 3d 83 [2] 7a 81 [2] 3d 90 [2] 73 9c [2] 7f 96 [2] 68 9d [2] 73 d3 [2] 4e }

  condition:
    any of them
}