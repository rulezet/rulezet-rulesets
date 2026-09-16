rule TTP_XOR_MULT_DOSStub_e21e {
  strings:
    $key_e21e = { b6 76 [2] c2 6e [2] 85 6c [2] c2 7d [2] 8c 71 [2] 80 7b [2] 97 70 [2] 8c 3e [2] b1 }

  condition:
    any of them
}