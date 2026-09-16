rule TTP_XOR_MULT_DOSStub_efec {
  strings:
    $key_efec = { bb 84 [2] cf 9c [2] 88 9e [2] cf 8f [2] 81 83 [2] 8d 89 [2] 9a 82 [2] 81 cc [2] bc }

  condition:
    any of them
}