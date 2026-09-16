rule TTP_XOR_MULT_DOSStub_beb9 {
  strings:
    $key_beb9 = { ea d1 [2] 9e c9 [2] d9 cb [2] 9e da [2] d0 d6 [2] dc dc [2] cb d7 [2] d0 99 [2] ed }

  condition:
    any of them
}