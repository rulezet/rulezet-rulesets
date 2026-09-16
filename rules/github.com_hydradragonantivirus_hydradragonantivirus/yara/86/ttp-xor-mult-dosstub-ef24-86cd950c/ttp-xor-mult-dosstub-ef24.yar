rule TTP_XOR_MULT_DOSStub_ef24 {
  strings:
    $key_ef24 = { bb 4c [2] cf 54 [2] 88 56 [2] cf 47 [2] 81 4b [2] 8d 41 [2] 9a 4a [2] 81 04 [2] bc }

  condition:
    any of them
}