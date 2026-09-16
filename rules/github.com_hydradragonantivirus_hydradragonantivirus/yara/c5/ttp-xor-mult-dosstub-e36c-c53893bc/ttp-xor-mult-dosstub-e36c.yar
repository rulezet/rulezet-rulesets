rule TTP_XOR_MULT_DOSStub_e36c {
  strings:
    $key_e36c = { b7 04 [2] c3 1c [2] 84 1e [2] c3 0f [2] 8d 03 [2] 81 09 [2] 96 02 [2] 8d 4c [2] b0 }

  condition:
    any of them
}