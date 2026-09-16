rule TTP_XOR_MULT_DOSStub_e76c {
  strings:
    $key_e76c = { b3 04 [2] c7 1c [2] 80 1e [2] c7 0f [2] 89 03 [2] 85 09 [2] 92 02 [2] 89 4c [2] b4 }

  condition:
    any of them
}