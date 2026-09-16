rule TTP_XOR_MULT_DOSStub_226c {
  strings:
    $key_226c = { 76 04 [2] 02 1c [2] 45 1e [2] 02 0f [2] 4c 03 [2] 40 09 [2] 57 02 [2] 4c 4c [2] 71 }

  condition:
    any of them
}