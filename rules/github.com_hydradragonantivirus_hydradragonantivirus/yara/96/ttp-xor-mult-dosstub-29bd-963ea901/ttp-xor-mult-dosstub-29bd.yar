rule TTP_XOR_MULT_DOSStub_29bd {
  strings:
    $key_29bd = { 7d d5 [2] 09 cd [2] 4e cf [2] 09 de [2] 47 d2 [2] 4b d8 [2] 5c d3 [2] 47 9d [2] 7a }

  condition:
    any of them
}