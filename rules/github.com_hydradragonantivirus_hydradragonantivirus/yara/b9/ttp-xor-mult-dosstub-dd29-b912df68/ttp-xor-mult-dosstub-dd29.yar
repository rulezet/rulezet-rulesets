rule TTP_XOR_MULT_DOSStub_dd29 {
  strings:
    $key_dd29 = { 89 41 [2] fd 59 [2] ba 5b [2] fd 4a [2] b3 46 [2] bf 4c [2] a8 47 [2] b3 09 [2] 8e }

  condition:
    any of them
}