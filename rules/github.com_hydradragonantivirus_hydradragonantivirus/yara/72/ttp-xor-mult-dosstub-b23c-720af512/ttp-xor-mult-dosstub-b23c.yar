rule TTP_XOR_MULT_DOSStub_b23c {
  strings:
    $key_b23c = { e6 54 [2] 92 4c [2] d5 4e [2] 92 5f [2] dc 53 [2] d0 59 [2] c7 52 [2] dc 1c [2] e1 }

  condition:
    any of them
}