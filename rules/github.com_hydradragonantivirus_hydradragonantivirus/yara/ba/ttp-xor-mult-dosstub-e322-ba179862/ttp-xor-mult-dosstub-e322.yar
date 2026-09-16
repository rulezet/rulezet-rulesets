rule TTP_XOR_MULT_DOSStub_e322 {
  strings:
    $key_e322 = { b7 4a [2] c3 52 [2] 84 50 [2] c3 41 [2] 8d 4d [2] 81 47 [2] 96 4c [2] 8d 02 [2] b0 }

  condition:
    any of them
}