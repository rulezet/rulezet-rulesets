rule TTP_XOR_MULT_DOSStub_e274 {
  strings:
    $key_e274 = { b6 1c [2] c2 04 [2] 85 06 [2] c2 17 [2] 8c 1b [2] 80 11 [2] 97 1a [2] 8c 54 [2] b1 }

  condition:
    any of them
}