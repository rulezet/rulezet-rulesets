rule TTP_XOR_MULT_DOSStub_f5bf {
  strings:
    $key_f5bf = { a1 d7 [2] d5 cf [2] 92 cd [2] d5 dc [2] 9b d0 [2] 97 da [2] 80 d1 [2] 9b 9f [2] a6 }

  condition:
    any of them
}