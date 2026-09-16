rule TTP_XOR_MULT_DOSStub_e3ed {
  strings:
    $key_e3ed = { b7 85 [2] c3 9d [2] 84 9f [2] c3 8e [2] 8d 82 [2] 81 88 [2] 96 83 [2] 8d cd [2] b0 }

  condition:
    any of them
}