rule TTP_XOR_MULT_DOSStub_b899 {
  strings:
    $key_b899 = { ec f1 [2] 98 e9 [2] df eb [2] 98 fa [2] d6 f6 [2] da fc [2] cd f7 [2] d6 b9 [2] eb }

  condition:
    any of them
}