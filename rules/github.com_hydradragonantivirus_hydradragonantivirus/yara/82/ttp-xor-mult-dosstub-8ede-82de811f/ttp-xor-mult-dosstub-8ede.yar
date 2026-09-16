rule TTP_XOR_MULT_DOSStub_8ede {
  strings:
    $key_8ede = { da b6 [2] ae ae [2] e9 ac [2] ae bd [2] e0 b1 [2] ec bb [2] fb b0 [2] e0 fe [2] dd }

  condition:
    any of them
}