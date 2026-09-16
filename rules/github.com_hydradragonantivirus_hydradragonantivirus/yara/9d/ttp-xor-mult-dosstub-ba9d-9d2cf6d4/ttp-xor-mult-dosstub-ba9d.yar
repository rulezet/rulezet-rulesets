rule TTP_XOR_MULT_DOSStub_ba9d {
  strings:
    $key_ba9d = { ee f5 [2] 9a ed [2] dd ef [2] 9a fe [2] d4 f2 [2] d8 f8 [2] cf f3 [2] d4 bd [2] e9 }

  condition:
    any of them
}