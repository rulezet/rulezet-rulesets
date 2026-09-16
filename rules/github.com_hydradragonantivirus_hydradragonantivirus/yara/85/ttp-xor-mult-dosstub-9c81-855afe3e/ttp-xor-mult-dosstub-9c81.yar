rule TTP_XOR_MULT_DOSStub_9c81 {
  strings:
    $key_9c81 = { c8 e9 [2] bc f1 [2] fb f3 [2] bc e2 [2] f2 ee [2] fe e4 [2] e9 ef [2] f2 a1 [2] cf }

  condition:
    any of them
}