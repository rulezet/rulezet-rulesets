rule TTP_XOR_MULT_DOSStub_b16c {
  strings:
    $key_b16c = { e5 04 [2] 91 1c [2] d6 1e [2] 91 0f [2] df 03 [2] d3 09 [2] c4 02 [2] df 4c [2] e2 }

  condition:
    any of them
}