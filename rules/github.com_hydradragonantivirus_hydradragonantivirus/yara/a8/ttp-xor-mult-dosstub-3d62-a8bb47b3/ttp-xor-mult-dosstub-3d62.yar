rule TTP_XOR_MULT_DOSStub_3d62 {
  strings:
    $key_3d62 = { 69 0a [2] 1d 12 [2] 5a 10 [2] 1d 01 [2] 53 0d [2] 5f 07 [2] 48 0c [2] 53 42 [2] 6e }

  condition:
    any of them
}