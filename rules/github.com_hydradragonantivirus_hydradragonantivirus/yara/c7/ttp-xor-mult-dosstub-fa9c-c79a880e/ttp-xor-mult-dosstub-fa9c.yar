rule TTP_XOR_MULT_DOSStub_fa9c {
  strings:
    $key_fa9c = { ae f4 [2] da ec [2] 9d ee [2] da ff [2] 94 f3 [2] 98 f9 [2] 8f f2 [2] 94 bc [2] a9 }

  condition:
    any of them
}