rule TTP_XOR_MULT_DOSStub_48f9 {
  strings:
    $key_48f9 = { 1c 91 [2] 68 89 [2] 2f 8b [2] 68 9a [2] 26 96 [2] 2a 9c [2] 3d 97 [2] 26 d9 [2] 1b }

  condition:
    any of them
}