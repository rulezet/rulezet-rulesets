rule TTP_XOR_MULT_DOSStub_669c {
  strings:
    $key_669c = { 32 f4 [2] 46 ec [2] 01 ee [2] 46 ff [2] 08 f3 [2] 04 f9 [2] 13 f2 [2] 08 bc [2] 35 }

  condition:
    any of them
}