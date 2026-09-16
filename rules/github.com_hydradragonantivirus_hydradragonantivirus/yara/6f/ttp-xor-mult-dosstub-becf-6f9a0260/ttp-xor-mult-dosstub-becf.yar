rule TTP_XOR_MULT_DOSStub_becf {
  strings:
    $key_becf = { ea a7 [2] 9e bf [2] d9 bd [2] 9e ac [2] d0 a0 [2] dc aa [2] cb a1 [2] d0 ef [2] ed }

  condition:
    any of them
}