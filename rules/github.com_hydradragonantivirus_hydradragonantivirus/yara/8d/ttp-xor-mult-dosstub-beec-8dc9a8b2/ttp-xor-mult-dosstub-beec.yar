rule TTP_XOR_MULT_DOSStub_beec {
  strings:
    $key_beec = { ea 84 [2] 9e 9c [2] d9 9e [2] 9e 8f [2] d0 83 [2] dc 89 [2] cb 82 [2] d0 cc [2] ed }

  condition:
    any of them
}