rule TTP_XOR_MULT_DOSStub_be9d {
  strings:
    $key_be9d = { ea f5 [2] 9e ed [2] d9 ef [2] 9e fe [2] d0 f2 [2] dc f8 [2] cb f3 [2] d0 bd [2] ed }

  condition:
    any of them
}