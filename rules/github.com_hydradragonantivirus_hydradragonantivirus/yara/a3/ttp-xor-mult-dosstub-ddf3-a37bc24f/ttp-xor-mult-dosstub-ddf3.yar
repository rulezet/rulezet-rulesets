rule TTP_XOR_MULT_DOSStub_ddf3 {
  strings:
    $key_ddf3 = { 89 9b [2] fd 83 [2] ba 81 [2] fd 90 [2] b3 9c [2] bf 96 [2] a8 9d [2] b3 d3 [2] 8e }

  condition:
    any of them
}