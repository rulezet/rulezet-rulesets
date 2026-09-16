rule TTP_XOR_MULT_DOSStub_3aef {
  strings:
    $key_3aef = { 6e 87 [2] 1a 9f [2] 5d 9d [2] 1a 8c [2] 54 80 [2] 58 8a [2] 4f 81 [2] 54 cf [2] 69 }

  condition:
    any of them
}