rule TTP_XOR_MULT_DOSStub_6e83 {
  strings:
    $key_6e83 = { 3a eb [2] 4e f3 [2] 09 f1 [2] 4e e0 [2] 00 ec [2] 0c e6 [2] 1b ed [2] 00 a3 [2] 3d }

  condition:
    any of them
}