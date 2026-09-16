rule TTP_XOR_MULT_DOSStub_2855 {
  strings:
    $key_2855 = { 7c 3d [2] 08 25 [2] 4f 27 [2] 08 36 [2] 46 3a [2] 4a 30 [2] 5d 3b [2] 46 75 [2] 7b }

  condition:
    any of them
}