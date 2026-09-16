rule TTP_XOR_MULT_DOSStub_288b {
  strings:
    $key_288b = { 7c e3 [2] 08 fb [2] 4f f9 [2] 08 e8 [2] 46 e4 [2] 4a ee [2] 5d e5 [2] 46 ab [2] 7b }

  condition:
    any of them
}