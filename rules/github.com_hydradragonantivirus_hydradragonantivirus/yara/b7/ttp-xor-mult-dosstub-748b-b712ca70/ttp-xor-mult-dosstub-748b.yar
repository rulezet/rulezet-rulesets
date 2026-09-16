rule TTP_XOR_MULT_DOSStub_748b {
  strings:
    $key_748b = { 20 e3 [2] 54 fb [2] 13 f9 [2] 54 e8 [2] 1a e4 [2] 16 ee [2] 01 e5 [2] 1a ab [2] 27 }

  condition:
    any of them
}