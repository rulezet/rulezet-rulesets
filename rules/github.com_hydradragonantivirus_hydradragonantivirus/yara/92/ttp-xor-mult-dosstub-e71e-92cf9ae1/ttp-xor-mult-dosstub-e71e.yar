rule TTP_XOR_MULT_DOSStub_e71e {
  strings:
    $key_e71e = { b3 76 [2] c7 6e [2] 80 6c [2] c7 7d [2] 89 71 [2] 85 7b [2] 92 70 [2] 89 3e [2] b4 }

  condition:
    any of them
}