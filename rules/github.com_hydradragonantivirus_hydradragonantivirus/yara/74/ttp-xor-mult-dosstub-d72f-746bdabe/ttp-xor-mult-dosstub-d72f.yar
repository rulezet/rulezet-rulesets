rule TTP_XOR_MULT_DOSStub_d72f {
  strings:
    $key_d72f = { 83 47 [2] f7 5f [2] b0 5d [2] f7 4c [2] b9 40 [2] b5 4a [2] a2 41 [2] b9 0f [2] 84 }

  condition:
    any of them
}