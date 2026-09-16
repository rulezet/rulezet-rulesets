rule TTP_XOR_MULT_DOSStub_ba97 {
  strings:
    $key_ba97 = { ee ff [2] 9a e7 [2] dd e5 [2] 9a f4 [2] d4 f8 [2] d8 f2 [2] cf f9 [2] d4 b7 [2] e9 }

  condition:
    any of them
}