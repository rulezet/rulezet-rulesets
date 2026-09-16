rule TTP_XOR_MULT_DOSStub_48fa {
  strings:
    $key_48fa = { 1c 92 [2] 68 8a [2] 2f 88 [2] 68 99 [2] 26 95 [2] 2a 9f [2] 3d 94 [2] 26 da [2] 1b }

  condition:
    any of them
}