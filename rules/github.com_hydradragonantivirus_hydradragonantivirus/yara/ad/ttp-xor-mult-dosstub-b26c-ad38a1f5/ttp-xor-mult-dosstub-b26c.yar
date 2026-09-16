rule TTP_XOR_MULT_DOSStub_b26c {
  strings:
    $key_b26c = { e6 04 [2] 92 1c [2] d5 1e [2] 92 0f [2] dc 03 [2] d0 09 [2] c7 02 [2] dc 4c [2] e1 }

  condition:
    any of them
}