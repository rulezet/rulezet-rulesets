rule TTP_XOR_MULT_DOSStub_5fcc {
  strings:
    $key_5fcc = { 0b a4 [2] 7f bc [2] 38 be [2] 7f af [2] 31 a3 [2] 3d a9 [2] 2a a2 [2] 31 ec [2] 0c }

  condition:
    any of them
}