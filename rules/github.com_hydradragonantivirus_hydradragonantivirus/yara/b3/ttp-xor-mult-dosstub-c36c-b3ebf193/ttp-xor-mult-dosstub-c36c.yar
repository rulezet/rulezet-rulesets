rule TTP_XOR_MULT_DOSStub_c36c {
  strings:
    $key_c36c = { 97 04 [2] e3 1c [2] a4 1e [2] e3 0f [2] ad 03 [2] a1 09 [2] b6 02 [2] ad 4c [2] 90 }

  condition:
    any of them
}