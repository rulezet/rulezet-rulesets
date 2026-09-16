rule TTP_XOR_MULT_DOSStub_ad88 {
  strings:
    $key_ad88 = { f9 e0 [2] 8d f8 [2] ca fa [2] 8d eb [2] c3 e7 [2] cf ed [2] d8 e6 [2] c3 a8 [2] fe }

  condition:
    any of them
}