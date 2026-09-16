rule TTP_XOR_MULT_DOSStub_2958 {
  strings:
    $key_2958 = { 7d 30 [2] 09 28 [2] 4e 2a [2] 09 3b [2] 47 37 [2] 4b 3d [2] 5c 36 [2] 47 78 [2] 7a }

  condition:
    any of them
}