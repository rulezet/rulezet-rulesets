rule TTP_XOR_MULT_DOSStub_fcce {
  strings:
    $key_fcce = { a8 a6 [2] dc be [2] 9b bc [2] dc ad [2] 92 a1 [2] 9e ab [2] 89 a0 [2] 92 ee [2] af }

  condition:
    any of them
}