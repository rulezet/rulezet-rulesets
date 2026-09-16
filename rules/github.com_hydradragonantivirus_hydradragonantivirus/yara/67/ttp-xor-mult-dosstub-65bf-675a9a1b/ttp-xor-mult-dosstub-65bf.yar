rule TTP_XOR_MULT_DOSStub_65bf {
  strings:
    $key_65bf = { 31 d7 [2] 45 cf [2] 02 cd [2] 45 dc [2] 0b d0 [2] 07 da [2] 10 d1 [2] 0b 9f [2] 36 }

  condition:
    any of them
}