rule TTP_XOR_MULT_DOSStub_6e39 {
  strings:
    $key_6e39 = { 3a 51 [2] 4e 49 [2] 09 4b [2] 4e 5a [2] 00 56 [2] 0c 5c [2] 1b 57 [2] 00 19 [2] 3d }

  condition:
    any of them
}