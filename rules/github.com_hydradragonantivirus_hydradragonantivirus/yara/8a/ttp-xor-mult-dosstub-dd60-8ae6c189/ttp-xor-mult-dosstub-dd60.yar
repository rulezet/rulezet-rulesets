rule TTP_XOR_MULT_DOSStub_dd60 {
  strings:
    $key_dd60 = { 89 08 [2] fd 10 [2] ba 12 [2] fd 03 [2] b3 0f [2] bf 05 [2] a8 0e [2] b3 40 [2] 8e }

  condition:
    any of them
}