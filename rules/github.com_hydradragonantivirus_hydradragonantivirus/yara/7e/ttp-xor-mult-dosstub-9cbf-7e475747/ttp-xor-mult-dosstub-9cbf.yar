rule TTP_XOR_MULT_DOSStub_9cbf {
  strings:
    $key_9cbf = { c8 d7 [2] bc cf [2] fb cd [2] bc dc [2] f2 d0 [2] fe da [2] e9 d1 [2] f2 9f [2] cf }

  condition:
    any of them
}