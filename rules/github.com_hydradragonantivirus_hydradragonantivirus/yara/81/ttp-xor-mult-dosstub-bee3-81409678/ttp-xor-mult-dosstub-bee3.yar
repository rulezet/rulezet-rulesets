rule TTP_XOR_MULT_DOSStub_bee3 {
  strings:
    $key_bee3 = { ea 8b [2] 9e 93 [2] d9 91 [2] 9e 80 [2] d0 8c [2] dc 86 [2] cb 8d [2] d0 c3 [2] ed }

  condition:
    any of them
}