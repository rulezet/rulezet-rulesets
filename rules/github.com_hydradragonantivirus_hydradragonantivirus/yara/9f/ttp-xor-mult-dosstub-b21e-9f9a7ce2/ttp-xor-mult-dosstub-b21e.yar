rule TTP_XOR_MULT_DOSStub_b21e {
  strings:
    $key_b21e = { e6 76 [2] 92 6e [2] d5 6c [2] 92 7d [2] dc 71 [2] d0 7b [2] c7 70 [2] dc 3e [2] e1 }

  condition:
    any of them
}