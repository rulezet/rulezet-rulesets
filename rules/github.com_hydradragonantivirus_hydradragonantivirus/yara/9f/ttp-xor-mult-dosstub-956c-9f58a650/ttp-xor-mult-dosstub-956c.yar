rule TTP_XOR_MULT_DOSStub_956c {
  strings:
    $key_956c = { c1 04 [2] b5 1c [2] f2 1e [2] b5 0f [2] fb 03 [2] f7 09 [2] e0 02 [2] fb 4c [2] c6 }

  condition:
    any of them
}