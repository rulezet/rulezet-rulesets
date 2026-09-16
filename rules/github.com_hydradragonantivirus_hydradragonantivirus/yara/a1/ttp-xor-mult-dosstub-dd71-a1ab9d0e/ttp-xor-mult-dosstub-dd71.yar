rule TTP_XOR_MULT_DOSStub_dd71 {
  strings:
    $key_dd71 = { 89 19 [2] fd 01 [2] ba 03 [2] fd 12 [2] b3 1e [2] bf 14 [2] a8 1f [2] b3 51 [2] 8e }

  condition:
    any of them
}