rule TTP_XOR_MULT_DOSStub_efce {
  strings:
    $key_efce = { bb a6 [2] cf be [2] 88 bc [2] cf ad [2] 81 a1 [2] 8d ab [2] 9a a0 [2] 81 ee [2] bc }

  condition:
    any of them
}