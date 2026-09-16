rule TTP_XOR_MULT_DOSStub_642f {
  strings:
    $key_642f = { 30 47 [2] 44 5f [2] 03 5d [2] 44 4c [2] 0a 40 [2] 06 4a [2] 11 41 [2] 0a 0f [2] 37 }

  condition:
    any of them
}