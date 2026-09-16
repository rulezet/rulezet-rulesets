rule TTP_XOR_MULT_DOSStub_be9b {
  strings:
    $key_be9b = { ea f3 [2] 9e eb [2] d9 e9 [2] 9e f8 [2] d0 f4 [2] dc fe [2] cb f5 [2] d0 bb [2] ed }

  condition:
    any of them
}