rule TTP_XOR_MULT_DOSStub_9b9c {
  strings:
    $key_9b9c = { cf f4 [2] bb ec [2] fc ee [2] bb ff [2] f5 f3 [2] f9 f9 [2] ee f2 [2] f5 bc [2] c8 }

  condition:
    any of them
}