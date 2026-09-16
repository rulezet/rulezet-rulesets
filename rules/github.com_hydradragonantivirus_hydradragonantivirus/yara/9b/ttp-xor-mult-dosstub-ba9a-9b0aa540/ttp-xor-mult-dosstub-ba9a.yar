rule TTP_XOR_MULT_DOSStub_ba9a {
  strings:
    $key_ba9a = { ee f2 [2] 9a ea [2] dd e8 [2] 9a f9 [2] d4 f5 [2] d8 ff [2] cf f4 [2] d4 ba [2] e9 }

  condition:
    any of them
}