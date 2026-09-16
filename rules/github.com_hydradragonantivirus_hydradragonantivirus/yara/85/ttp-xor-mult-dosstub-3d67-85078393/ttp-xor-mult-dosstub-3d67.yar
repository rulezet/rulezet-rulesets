rule TTP_XOR_MULT_DOSStub_3d67 {
  strings:
    $key_3d67 = { 69 0f [2] 1d 17 [2] 5a 15 [2] 1d 04 [2] 53 08 [2] 5f 02 [2] 48 09 [2] 53 47 [2] 6e }

  condition:
    any of them
}