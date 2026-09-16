rule TTP_XOR_MULT_DOSStub_e329 {
  strings:
    $key_e329 = { b7 41 [2] c3 59 [2] 84 5b [2] c3 4a [2] 8d 46 [2] 81 4c [2] 96 47 [2] 8d 09 [2] b0 }

  condition:
    any of them
}