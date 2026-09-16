rule TTP_XOR_MULT_DOSStub_2bbf {
  strings:
    $key_2bbf = { 7f d7 [2] 0b cf [2] 4c cd [2] 0b dc [2] 45 d0 [2] 49 da [2] 5e d1 [2] 45 9f [2] 78 }

  condition:
    any of them
}