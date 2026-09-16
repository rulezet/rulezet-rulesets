rule TTP_XOR_MULT_DOSStub_2955 {
  strings:
    $key_2955 = { 7d 3d [2] 09 25 [2] 4e 27 [2] 09 36 [2] 47 3a [2] 4b 30 [2] 5c 3b [2] 47 75 [2] 7a }

  condition:
    any of them
}