rule TTP_XOR_MULT_DOSStub_beff {
  strings:
    $key_beff = { ea 97 [2] 9e 8f [2] d9 8d [2] 9e 9c [2] d0 90 [2] dc 9a [2] cb 91 [2] d0 df [2] ed }

  condition:
    any of them
}