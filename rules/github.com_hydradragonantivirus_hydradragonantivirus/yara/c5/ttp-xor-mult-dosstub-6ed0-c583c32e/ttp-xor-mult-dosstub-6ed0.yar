rule TTP_XOR_MULT_DOSStub_6ed0 {
  strings:
    $key_6ed0 = { 3a b8 [2] 4e a0 [2] 09 a2 [2] 4e b3 [2] 00 bf [2] 0c b5 [2] 1b be [2] 00 f0 [2] 3d }

  condition:
    any of them
}