rule TTP_XOR_MULT_DOSStub_1bbf {
  strings:
    $key_1bbf = { 4f d7 [2] 3b cf [2] 7c cd [2] 3b dc [2] 75 d0 [2] 79 da [2] 6e d1 [2] 75 9f [2] 48 }

  condition:
    any of them
}