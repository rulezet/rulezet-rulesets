rule TTP_XOR_MULT_DOSStub_b2ed {
  strings:
    $key_b2ed = { e6 85 [2] 92 9d [2] d5 9f [2] 92 8e [2] dc 82 [2] d0 88 [2] c7 83 [2] dc cd [2] e1 }

  condition:
    any of them
}