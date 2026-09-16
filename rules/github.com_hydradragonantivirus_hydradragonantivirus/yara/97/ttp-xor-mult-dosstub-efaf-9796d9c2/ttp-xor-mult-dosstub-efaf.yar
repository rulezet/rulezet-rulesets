rule TTP_XOR_MULT_DOSStub_efaf {
  strings:
    $key_efaf = { bb c7 [2] cf df [2] 88 dd [2] cf cc [2] 81 c0 [2] 8d ca [2] 9a c1 [2] 81 8f [2] bc }

  condition:
    any of them
}