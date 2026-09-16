rule TTP_XOR_MULT_DOSStub_e323 {
  strings:
    $key_e323 = { b7 4b [2] c3 53 [2] 84 51 [2] c3 40 [2] 8d 4c [2] 81 46 [2] 96 4d [2] 8d 03 [2] b0 }

  condition:
    any of them
}