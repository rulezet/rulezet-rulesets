rule TTP_XOR_MULT_DOSStub_48f4 {
  strings:
    $key_48f4 = { 1c 9c [2] 68 84 [2] 2f 86 [2] 68 97 [2] 26 9b [2] 2a 91 [2] 3d 9a [2] 26 d4 [2] 1b }

  condition:
    any of them
}