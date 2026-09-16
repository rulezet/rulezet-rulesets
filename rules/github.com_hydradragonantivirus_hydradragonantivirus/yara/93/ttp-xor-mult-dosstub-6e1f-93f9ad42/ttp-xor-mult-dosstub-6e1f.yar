rule TTP_XOR_MULT_DOSStub_6e1f {
  strings:
    $key_6e1f = { 3a 77 [2] 4e 6f [2] 09 6d [2] 4e 7c [2] 00 70 [2] 0c 7a [2] 1b 71 [2] 00 3f [2] 3d }

  condition:
    any of them
}