rule TTP_XOR_MULT_DOSStub_e324 {
  strings:
    $key_e324 = { b7 4c [2] c3 54 [2] 84 56 [2] c3 47 [2] 8d 4b [2] 81 41 [2] 96 4a [2] 8d 04 [2] b0 }

  condition:
    any of them
}