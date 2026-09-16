rule TTP_XOR_MULT_DOSStub_be6a {
  strings:
    $key_be6a = { ea 02 [2] 9e 1a [2] d9 18 [2] 9e 09 [2] d0 05 [2] dc 0f [2] cb 04 [2] d0 4a [2] ed }

  condition:
    any of them
}