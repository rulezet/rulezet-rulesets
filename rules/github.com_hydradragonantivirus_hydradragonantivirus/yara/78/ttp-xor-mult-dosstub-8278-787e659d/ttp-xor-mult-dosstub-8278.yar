rule TTP_XOR_MULT_DOSStub_8278 {
  strings:
    $key_8278 = { d6 10 [2] a2 08 [2] e5 0a [2] a2 1b [2] ec 17 [2] e0 1d [2] f7 16 [2] ec 58 [2] d1 }

  condition:
    any of them
}