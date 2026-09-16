rule TTP_XOR_MULT_DOSStub_c423 {
  strings:
    $key_c423 = { 90 4b [2] e4 53 [2] a3 51 [2] e4 40 [2] aa 4c [2] a6 46 [2] b1 4d [2] aa 03 [2] 97 }

  condition:
    any of them
}