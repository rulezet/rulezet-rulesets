rule TTP_XOR_MULT_DOSStub_5cbd {
  strings:
    $key_5cbd = { 08 d5 [2] 7c cd [2] 3b cf [2] 7c de [2] 32 d2 [2] 3e d8 [2] 29 d3 [2] 32 9d [2] 0f }

  condition:
    any of them
}