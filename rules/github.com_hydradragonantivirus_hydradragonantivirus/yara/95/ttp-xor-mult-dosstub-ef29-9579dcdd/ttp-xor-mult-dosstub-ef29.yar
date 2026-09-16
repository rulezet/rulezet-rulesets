rule TTP_XOR_MULT_DOSStub_ef29 {
  strings:
    $key_ef29 = { bb 41 [2] cf 59 [2] 88 5b [2] cf 4a [2] 81 46 [2] 8d 4c [2] 9a 47 [2] 81 09 [2] bc }

  condition:
    any of them
}