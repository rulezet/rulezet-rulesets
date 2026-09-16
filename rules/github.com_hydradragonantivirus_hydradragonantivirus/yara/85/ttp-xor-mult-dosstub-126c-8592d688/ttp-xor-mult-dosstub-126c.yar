rule TTP_XOR_MULT_DOSStub_126c {
  strings:
    $key_126c = { 46 04 [2] 32 1c [2] 75 1e [2] 32 0f [2] 7c 03 [2] 70 09 [2] 67 02 [2] 7c 4c [2] 41 }

  condition:
    any of them
}