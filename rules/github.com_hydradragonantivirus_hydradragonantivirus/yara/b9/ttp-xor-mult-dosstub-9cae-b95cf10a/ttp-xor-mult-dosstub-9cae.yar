rule TTP_XOR_MULT_DOSStub_9cae {
  strings:
    $key_9cae = { c8 c6 [2] bc de [2] fb dc [2] bc cd [2] f2 c1 [2] fe cb [2] e9 c0 [2] f2 8e [2] cf }

  condition:
    any of them
}