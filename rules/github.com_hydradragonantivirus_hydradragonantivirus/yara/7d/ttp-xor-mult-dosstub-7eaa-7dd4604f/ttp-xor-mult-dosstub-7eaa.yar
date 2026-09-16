rule TTP_XOR_MULT_DOSStub_7eaa {
  strings:
    $key_7eaa = { 2a c2 [2] 5e da [2] 19 d8 [2] 5e c9 [2] 10 c5 [2] 1c cf [2] 0b c4 [2] 10 8a [2] 2d }

  condition:
    any of them
}