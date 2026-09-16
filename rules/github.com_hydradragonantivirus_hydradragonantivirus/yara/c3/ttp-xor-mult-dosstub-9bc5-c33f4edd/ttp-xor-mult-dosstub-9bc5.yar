rule TTP_XOR_MULT_DOSStub_9bc5 {
  strings:
    $key_9bc5 = { cf ad [2] bb b5 [2] fc b7 [2] bb a6 [2] f5 aa [2] f9 a0 [2] ee ab [2] f5 e5 [2] c8 }

  condition:
    any of them
}