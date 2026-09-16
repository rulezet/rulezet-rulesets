rule TTP_XOR_MULT_DOSStub_482c {
  strings:
    $key_482c = { 1c 44 [2] 68 5c [2] 2f 5e [2] 68 4f [2] 26 43 [2] 2a 49 [2] 3d 42 [2] 26 0c [2] 1b }

  condition:
    any of them
}