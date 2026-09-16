rule TTP_XOR_MULT_DOSStub_ba90 {
  strings:
    $key_ba90 = { ee f8 [2] 9a e0 [2] dd e2 [2] 9a f3 [2] d4 ff [2] d8 f5 [2] cf fe [2] d4 b0 [2] e9 }

  condition:
    any of them
}