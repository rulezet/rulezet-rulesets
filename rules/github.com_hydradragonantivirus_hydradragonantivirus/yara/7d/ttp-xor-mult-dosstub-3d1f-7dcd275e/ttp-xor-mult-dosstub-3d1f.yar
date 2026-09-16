rule TTP_XOR_MULT_DOSStub_3d1f {
  strings:
    $key_3d1f = { 69 77 [2] 1d 6f [2] 5a 6d [2] 1d 7c [2] 53 70 [2] 5f 7a [2] 48 71 [2] 53 3f [2] 6e }

  condition:
    any of them
}