rule TTP_XOR_MULT_DOSStub_be4f {
  strings:
    $key_be4f = { ea 27 [2] 9e 3f [2] d9 3d [2] 9e 2c [2] d0 20 [2] dc 2a [2] cb 21 [2] d0 6f [2] ed }

  condition:
    any of them
}