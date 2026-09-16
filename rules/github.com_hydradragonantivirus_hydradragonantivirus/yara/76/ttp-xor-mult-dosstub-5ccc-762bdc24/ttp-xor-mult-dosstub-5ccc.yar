rule TTP_XOR_MULT_DOSStub_5ccc {
  strings:
    $key_5ccc = { 08 a4 [2] 7c bc [2] 3b be [2] 7c af [2] 32 a3 [2] 3e a9 [2] 29 a2 [2] 32 ec [2] 0f }

  condition:
    any of them
}