rule TTP_XOR_MULT_DOSStub_483d {
  strings:
    $key_483d = { 1c 55 [2] 68 4d [2] 2f 4f [2] 68 5e [2] 26 52 [2] 2a 58 [2] 3d 53 [2] 26 1d [2] 1b }

  condition:
    any of them
}