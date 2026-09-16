rule TTP_XOR_MULT_DOSStub_06a2 {
  strings:
    $key_06a2 = { 52 ca [2] 26 d2 [2] 61 d0 [2] 26 c1 [2] 68 cd [2] 64 c7 [2] 73 cc [2] 68 82 [2] 55 }

  condition:
    any of them
}