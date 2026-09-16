rule TTP_XOR_MULT_DOSStub_2fcc {
  strings:
    $key_2fcc = { 7b a4 [2] 0f bc [2] 48 be [2] 0f af [2] 41 a3 [2] 4d a9 [2] 5a a2 [2] 41 ec [2] 7c }

  condition:
    any of them
}