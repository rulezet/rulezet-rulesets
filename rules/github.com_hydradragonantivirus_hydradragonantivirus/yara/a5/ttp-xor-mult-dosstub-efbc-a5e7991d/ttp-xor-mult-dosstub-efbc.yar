rule TTP_XOR_MULT_DOSStub_efbc {
  strings:
    $key_efbc = { bb d4 [2] cf cc [2] 88 ce [2] cf df [2] 81 d3 [2] 8d d9 [2] 9a d2 [2] 81 9c [2] bc }

  condition:
    any of them
}