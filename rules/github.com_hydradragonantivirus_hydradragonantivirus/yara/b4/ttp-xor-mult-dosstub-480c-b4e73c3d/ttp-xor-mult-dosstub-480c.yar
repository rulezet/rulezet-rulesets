rule TTP_XOR_MULT_DOSStub_480c {
  strings:
    $key_480c = { 1c 64 [2] 68 7c [2] 2f 7e [2] 68 6f [2] 26 63 [2] 2a 69 [2] 3d 62 [2] 26 2c [2] 1b }

  condition:
    any of them
}