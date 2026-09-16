rule TTP_XOR_MULT_DOSStub_316c {
  strings:
    $key_316c = { 65 04 [2] 11 1c [2] 56 1e [2] 11 0f [2] 5f 03 [2] 53 09 [2] 44 02 [2] 5f 4c [2] 62 }

  condition:
    any of them
}