rule TTP_XOR_MULT_DOSStub_3bbf {
  strings:
    $key_3bbf = { 6f d7 [2] 1b cf [2] 5c cd [2] 1b dc [2] 55 d0 [2] 59 da [2] 4e d1 [2] 55 9f [2] 68 }

  condition:
    any of them
}