rule TTP_XOR_MULT_DOSStub_2e6c {
  strings:
    $key_2e6c = { 7a 04 [2] 0e 1c [2] 49 1e [2] 0e 0f [2] 40 03 [2] 4c 09 [2] 5b 02 [2] 40 4c [2] 7d }

  condition:
    any of them
}