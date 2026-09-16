rule TTP_XOR_MULT_DOSStub_7ccc {
  strings:
    $key_7ccc = { 28 a4 [2] 5c bc [2] 1b be [2] 5c af [2] 12 a3 [2] 1e a9 [2] 09 a2 [2] 12 ec [2] 2f }

  condition:
    any of them
}