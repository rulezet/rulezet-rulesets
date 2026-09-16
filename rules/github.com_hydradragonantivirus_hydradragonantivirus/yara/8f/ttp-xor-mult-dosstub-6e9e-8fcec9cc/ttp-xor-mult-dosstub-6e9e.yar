rule TTP_XOR_MULT_DOSStub_6e9e {
  strings:
    $key_6e9e = { 3a f6 [2] 4e ee [2] 09 ec [2] 4e fd [2] 00 f1 [2] 0c fb [2] 1b f0 [2] 00 be [2] 3d }

  condition:
    any of them
}