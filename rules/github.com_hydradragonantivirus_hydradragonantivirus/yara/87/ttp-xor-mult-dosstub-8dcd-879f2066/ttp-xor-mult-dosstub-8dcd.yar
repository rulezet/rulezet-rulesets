rule TTP_XOR_MULT_DOSStub_8dcd {
  strings:
    $key_8dcd = { d9 a5 [2] ad bd [2] ea bf [2] ad ae [2] e3 a2 [2] ef a8 [2] f8 a3 [2] e3 ed [2] de }

  condition:
    any of them
}