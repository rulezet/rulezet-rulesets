rule TTP_XOR_MULT_DOSStub_dd2c {
  strings:
    $key_dd2c = { 89 44 [2] fd 5c [2] ba 5e [2] fd 4f [2] b3 43 [2] bf 49 [2] a8 42 [2] b3 0c [2] 8e }

  condition:
    any of them
}