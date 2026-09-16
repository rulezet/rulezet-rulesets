rule TTP_XOR_MULT_DOSStub_bef2 {
  strings:
    $key_bef2 = { ea 9a [2] 9e 82 [2] d9 80 [2] 9e 91 [2] d0 9d [2] dc 97 [2] cb 9c [2] d0 d2 [2] ed }

  condition:
    any of them
}