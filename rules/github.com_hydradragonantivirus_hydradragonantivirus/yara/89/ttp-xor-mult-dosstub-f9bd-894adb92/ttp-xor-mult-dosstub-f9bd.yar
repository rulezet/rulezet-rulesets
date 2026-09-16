rule TTP_XOR_MULT_DOSStub_f9bd {
  strings:
    $key_f9bd = { ad d5 [2] d9 cd [2] 9e cf [2] d9 de [2] 97 d2 [2] 9b d8 [2] 8c d3 [2] 97 9d [2] aa }

  condition:
    any of them
}