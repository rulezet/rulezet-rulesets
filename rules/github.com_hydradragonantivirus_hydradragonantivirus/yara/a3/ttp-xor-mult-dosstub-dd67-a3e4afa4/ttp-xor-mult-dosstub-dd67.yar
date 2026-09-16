rule TTP_XOR_MULT_DOSStub_dd67 {
  strings:
    $key_dd67 = { 89 0f [2] fd 17 [2] ba 15 [2] fd 04 [2] b3 08 [2] bf 02 [2] a8 09 [2] b3 47 [2] 8e }

  condition:
    any of them
}