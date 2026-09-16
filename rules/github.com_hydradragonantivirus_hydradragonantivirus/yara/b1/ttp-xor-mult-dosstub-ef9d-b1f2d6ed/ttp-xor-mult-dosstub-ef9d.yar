rule TTP_XOR_MULT_DOSStub_ef9d {
  strings:
    $key_ef9d = { bb f5 [2] cf ed [2] 88 ef [2] cf fe [2] 81 f2 [2] 8d f8 [2] 9a f3 [2] 81 bd [2] bc }

  condition:
    any of them
}