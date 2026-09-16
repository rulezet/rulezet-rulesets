rule TTP_XOR_MULT_DOSStub_826f {
  strings:
    $key_826f = { d6 07 [2] a2 1f [2] e5 1d [2] a2 0c [2] ec 00 [2] e0 0a [2] f7 01 [2] ec 4f [2] d1 }

  condition:
    any of them
}