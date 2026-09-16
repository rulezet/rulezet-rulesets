rule TTP_XOR_MULT_DOSStub_69af {
  strings:
    $key_69af = { 3d c7 [2] 49 df [2] 0e dd [2] 49 cc [2] 07 c0 [2] 0b ca [2] 1c c1 [2] 07 8f [2] 3a }

  condition:
    any of them
}