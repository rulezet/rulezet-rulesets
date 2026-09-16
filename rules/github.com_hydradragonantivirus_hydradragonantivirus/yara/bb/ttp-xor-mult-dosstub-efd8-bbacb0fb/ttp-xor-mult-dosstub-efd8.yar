rule TTP_XOR_MULT_DOSStub_efd8 {
  strings:
    $key_efd8 = { bb b0 [2] cf a8 [2] 88 aa [2] cf bb [2] 81 b7 [2] 8d bd [2] 9a b6 [2] 81 f8 [2] bc }

  condition:
    any of them
}