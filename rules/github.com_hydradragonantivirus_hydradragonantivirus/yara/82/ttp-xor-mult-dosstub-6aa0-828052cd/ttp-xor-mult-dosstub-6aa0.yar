rule TTP_XOR_MULT_DOSStub_6aa0 {
  strings:
    $key_6aa0 = { 3e c8 [2] 4a d0 [2] 0d d2 [2] 4a c3 [2] 04 cf [2] 08 c5 [2] 1f ce [2] 04 80 [2] 39 }

  condition:
    any of them
}