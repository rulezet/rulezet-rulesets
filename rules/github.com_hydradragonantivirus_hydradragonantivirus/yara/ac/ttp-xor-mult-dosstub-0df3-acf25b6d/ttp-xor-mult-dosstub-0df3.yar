rule TTP_XOR_MULT_DOSStub_0df3 {
  strings:
    $key_0df3 = { 59 9b [2] 2d 83 [2] 6a 81 [2] 2d 90 [2] 63 9c [2] 6f 96 [2] 78 9d [2] 63 d3 [2] 5e }

  condition:
    any of them
}