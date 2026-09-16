rule TTP_XOR_MULT_DOSStub_93bd {
  strings:
    $key_93bd = { c7 d5 [2] b3 cd [2] f4 cf [2] b3 de [2] fd d2 [2] f1 d8 [2] e6 d3 [2] fd 9d [2] c0 }

  condition:
    any of them
}