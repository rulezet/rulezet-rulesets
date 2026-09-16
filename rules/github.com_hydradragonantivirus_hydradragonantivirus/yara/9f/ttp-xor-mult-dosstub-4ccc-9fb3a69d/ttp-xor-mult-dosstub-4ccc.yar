rule TTP_XOR_MULT_DOSStub_4ccc {
  strings:
    $key_4ccc = { 18 a4 [2] 6c bc [2] 2b be [2] 6c af [2] 22 a3 [2] 2e a9 [2] 39 a2 [2] 22 ec [2] 1f }

  condition:
    any of them
}