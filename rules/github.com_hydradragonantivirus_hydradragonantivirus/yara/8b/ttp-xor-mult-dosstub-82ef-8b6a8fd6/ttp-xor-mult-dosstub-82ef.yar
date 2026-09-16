rule TTP_XOR_MULT_DOSStub_82ef {
  strings:
    $key_82ef = { d6 87 [2] a2 9f [2] e5 9d [2] a2 8c [2] ec 80 [2] e0 8a [2] f7 81 [2] ec cf [2] d1 }

  condition:
    any of them
}