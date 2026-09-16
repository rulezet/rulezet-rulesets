rule TTP_XOR_MULT_DOSStub_48cb {
  strings:
    $key_48cb = { 1c a3 [2] 68 bb [2] 2f b9 [2] 68 a8 [2] 26 a4 [2] 2a ae [2] 3d a5 [2] 26 eb [2] 1b }

  condition:
    any of them
}