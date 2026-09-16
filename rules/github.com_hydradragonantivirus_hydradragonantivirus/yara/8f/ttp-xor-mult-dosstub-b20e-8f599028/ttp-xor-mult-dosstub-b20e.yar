rule TTP_XOR_MULT_DOSStub_b20e {
  strings:
    $key_b20e = { e6 66 [2] 92 7e [2] d5 7c [2] 92 6d [2] dc 61 [2] d0 6b [2] c7 60 [2] dc 2e [2] e1 }

  condition:
    any of them
}