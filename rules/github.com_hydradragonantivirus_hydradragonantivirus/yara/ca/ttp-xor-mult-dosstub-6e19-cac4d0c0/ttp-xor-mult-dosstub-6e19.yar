rule TTP_XOR_MULT_DOSStub_6e19 {
  strings:
    $key_6e19 = { 3a 71 [2] 4e 69 [2] 09 6b [2] 4e 7a [2] 00 76 [2] 0c 7c [2] 1b 77 [2] 00 39 [2] 3d }

  condition:
    any of them
}