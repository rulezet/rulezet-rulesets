rule TTP_XOR_MULT_DOSStub_9ccd {
  strings:
    $key_9ccd = { c8 a5 [2] bc bd [2] fb bf [2] bc ae [2] f2 a2 [2] fe a8 [2] e9 a3 [2] f2 ed [2] cf }

  condition:
    any of them
}