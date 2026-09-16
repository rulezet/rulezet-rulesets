rule TTP_XOR_MULT_DOSStub_beed {
  strings:
    $key_beed = { ea 85 [2] 9e 9d [2] d9 9f [2] 9e 8e [2] d0 82 [2] dc 88 [2] cb 83 [2] d0 cd [2] ed }

  condition:
    any of them
}