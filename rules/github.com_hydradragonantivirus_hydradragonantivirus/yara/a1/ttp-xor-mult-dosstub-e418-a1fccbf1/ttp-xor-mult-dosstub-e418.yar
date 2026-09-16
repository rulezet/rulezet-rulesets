rule TTP_XOR_MULT_DOSStub_e418 {
  strings:
    $key_e418 = { b0 70 [2] c4 68 [2] 83 6a [2] c4 7b [2] 8a 77 [2] 86 7d [2] 91 76 [2] 8a 38 [2] b7 }

  condition:
    any of them
}