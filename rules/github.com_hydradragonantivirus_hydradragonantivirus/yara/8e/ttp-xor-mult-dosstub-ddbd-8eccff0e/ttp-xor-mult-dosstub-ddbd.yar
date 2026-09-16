rule TTP_XOR_MULT_DOSStub_ddbd {
  strings:
    $key_ddbd = { 89 d5 [2] fd cd [2] ba cf [2] fd de [2] b3 d2 [2] bf d8 [2] a8 d3 [2] b3 9d [2] 8e }

  condition:
    any of them
}