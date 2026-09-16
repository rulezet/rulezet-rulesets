rule TTP_XOR_MULT_DOSStub_6939 {
  strings:
    $key_6939 = { 3d 51 [2] 49 49 [2] 0e 4b [2] 49 5a [2] 07 56 [2] 0b 5c [2] 1c 57 [2] 07 19 [2] 3a }

  condition:
    any of them
}