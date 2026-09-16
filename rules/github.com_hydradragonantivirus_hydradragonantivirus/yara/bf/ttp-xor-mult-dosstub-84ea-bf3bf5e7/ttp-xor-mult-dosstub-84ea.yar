rule TTP_XOR_MULT_DOSStub_84ea {
  strings:
    $key_84ea = { d0 82 [2] a4 9a [2] e3 98 [2] a4 89 [2] ea 85 [2] e6 8f [2] f1 84 [2] ea ca [2] d7 }

  condition:
    any of them
}