rule TTP_XOR_MULT_DOSStub_dd37 {
  strings:
    $key_dd37 = { 89 5f [2] fd 47 [2] ba 45 [2] fd 54 [2] b3 58 [2] bf 52 [2] a8 59 [2] b3 17 [2] 8e }

  condition:
    any of them
}