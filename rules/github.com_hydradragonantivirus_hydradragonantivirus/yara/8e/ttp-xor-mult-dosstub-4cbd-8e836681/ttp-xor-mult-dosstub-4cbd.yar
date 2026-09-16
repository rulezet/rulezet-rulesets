rule TTP_XOR_MULT_DOSStub_4cbd {
  strings:
    $key_4cbd = { 18 d5 [2] 6c cd [2] 2b cf [2] 6c de [2] 22 d2 [2] 2e d8 [2] 39 d3 [2] 22 9d [2] 1f }

  condition:
    any of them
}