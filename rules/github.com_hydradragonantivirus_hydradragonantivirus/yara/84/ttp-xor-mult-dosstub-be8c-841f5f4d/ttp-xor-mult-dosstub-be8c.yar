rule TTP_XOR_MULT_DOSStub_be8c {
  strings:
    $key_be8c = { ea e4 [2] 9e fc [2] d9 fe [2] 9e ef [2] d0 e3 [2] dc e9 [2] cb e2 [2] d0 ac [2] ed }

  condition:
    any of them
}