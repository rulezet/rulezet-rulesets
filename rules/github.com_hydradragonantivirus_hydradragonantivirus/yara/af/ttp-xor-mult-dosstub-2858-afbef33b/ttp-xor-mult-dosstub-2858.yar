rule TTP_XOR_MULT_DOSStub_2858 {
  strings:
    $key_2858 = { 7c 30 [2] 08 28 [2] 4f 2a [2] 08 3b [2] 46 37 [2] 4a 3d [2] 5d 36 [2] 46 78 [2] 7b }

  condition:
    any of them
}