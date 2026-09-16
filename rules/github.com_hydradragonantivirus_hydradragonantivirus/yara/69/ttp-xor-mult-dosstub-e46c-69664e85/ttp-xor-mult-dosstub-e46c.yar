rule TTP_XOR_MULT_DOSStub_e46c {
  strings:
    $key_e46c = { b0 04 [2] c4 1c [2] 83 1e [2] c4 0f [2] 8a 03 [2] 86 09 [2] 91 02 [2] 8a 4c [2] b7 }

  condition:
    any of them
}