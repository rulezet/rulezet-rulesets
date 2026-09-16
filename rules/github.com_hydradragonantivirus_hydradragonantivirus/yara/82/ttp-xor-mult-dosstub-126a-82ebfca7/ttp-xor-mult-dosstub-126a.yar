rule TTP_XOR_MULT_DOSStub_126a {
  strings:
    $key_126a = { 46 02 [2] 32 1a [2] 75 18 [2] 32 09 [2] 7c 05 [2] 70 0f [2] 67 04 [2] 7c 4a [2] 41 }

  condition:
    any of them
}