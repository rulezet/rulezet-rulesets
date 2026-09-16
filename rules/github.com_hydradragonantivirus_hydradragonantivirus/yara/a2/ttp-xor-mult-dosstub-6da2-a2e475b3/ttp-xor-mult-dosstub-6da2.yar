rule TTP_XOR_MULT_DOSStub_6da2 {
  strings:
    $key_6da2 = { 39 ca [2] 4d d2 [2] 0a d0 [2] 4d c1 [2] 03 cd [2] 0f c7 [2] 18 cc [2] 03 82 [2] 3e }

  condition:
    any of them
}