rule TTP_XOR_MULT_DOSStub_babf {
  strings:
    $key_babf = { ee d7 [2] 9a cf [2] dd cd [2] 9a dc [2] d4 d0 [2] d8 da [2] cf d1 [2] d4 9f [2] e9 }

  condition:
    any of them
}