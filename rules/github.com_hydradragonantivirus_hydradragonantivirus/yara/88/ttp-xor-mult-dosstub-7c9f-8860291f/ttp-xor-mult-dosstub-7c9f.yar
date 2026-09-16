rule TTP_XOR_MULT_DOSStub_7c9f {
  strings:
    $key_7c9f = { 28 f7 [2] 5c ef [2] 1b ed [2] 5c fc [2] 12 f0 [2] 1e fa [2] 09 f1 [2] 12 bf [2] 2f }

  condition:
    any of them
}