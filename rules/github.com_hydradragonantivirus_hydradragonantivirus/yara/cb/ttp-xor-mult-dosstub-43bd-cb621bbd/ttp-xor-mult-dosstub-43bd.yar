rule TTP_XOR_MULT_DOSStub_43bd {
  strings:
    $key_43bd = { 17 d5 [2] 63 cd [2] 24 cf [2] 63 de [2] 2d d2 [2] 21 d8 [2] 36 d3 [2] 2d 9d [2] 10 }

  condition:
    any of them
}