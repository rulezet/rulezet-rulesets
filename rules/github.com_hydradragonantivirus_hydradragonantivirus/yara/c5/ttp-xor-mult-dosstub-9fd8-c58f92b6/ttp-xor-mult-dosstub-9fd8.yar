rule TTP_XOR_MULT_DOSStub_9fd8 {
  strings:
    $key_9fd8 = { cb b0 [2] bf a8 [2] f8 aa [2] bf bb [2] f1 b7 [2] fd bd [2] ea b6 [2] f1 f8 [2] cc }

  condition:
    any of them
}