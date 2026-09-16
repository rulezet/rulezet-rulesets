rule TTP_XOR_MULT_DOSStub_dede {
  strings:
    $key_dede = { 8a b6 [2] fe ae [2] b9 ac [2] fe bd [2] b0 b1 [2] bc bb [2] ab b0 [2] b0 fe [2] 8d }

  condition:
    any of them
}