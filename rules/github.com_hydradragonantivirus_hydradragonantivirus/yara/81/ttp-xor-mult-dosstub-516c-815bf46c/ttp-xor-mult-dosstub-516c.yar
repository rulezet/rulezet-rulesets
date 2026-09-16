rule TTP_XOR_MULT_DOSStub_516c {
  strings:
    $key_516c = { 05 04 [2] 71 1c [2] 36 1e [2] 71 0f [2] 3f 03 [2] 33 09 [2] 24 02 [2] 3f 4c [2] 02 }

  condition:
    any of them
}