rule TTP_XOR_MULT_DOSStub_ad8c {
  strings:
    $key_ad8c = { f9 e4 [2] 8d fc [2] ca fe [2] 8d ef [2] c3 e3 [2] cf e9 [2] d8 e2 [2] c3 ac [2] fe }

  condition:
    any of them
}