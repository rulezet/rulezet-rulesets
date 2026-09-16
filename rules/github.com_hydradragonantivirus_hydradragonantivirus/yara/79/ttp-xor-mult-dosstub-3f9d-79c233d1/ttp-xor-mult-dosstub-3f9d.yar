rule TTP_XOR_MULT_DOSStub_3f9d {
  strings:
    $key_3f9d = { 6b f5 [2] 1f ed [2] 58 ef [2] 1f fe [2] 51 f2 [2] 5d f8 [2] 4a f3 [2] 51 bd [2] 6c }

  condition:
    any of them
}