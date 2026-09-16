rule TTP_XOR_MULT_DOSStub_6b05 {
  strings:
    $key_6b05 = { 3f 6d [2] 4b 75 [2] 0c 77 [2] 4b 66 [2] 05 6a [2] 09 60 [2] 1e 6b [2] 05 25 [2] 38 }

  condition:
    any of them
}