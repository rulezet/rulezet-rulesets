rule TTP_XOR_MULT_DOSStub_6994 {
  strings:
    $key_6994 = { 3d fc [2] 49 e4 [2] 0e e6 [2] 49 f7 [2] 07 fb [2] 0b f1 [2] 1c fa [2] 07 b4 [2] 3a }

  condition:
    any of them
}