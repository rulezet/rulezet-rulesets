rule TTP_XOR_MULT_DOSStub_3e6c {
  strings:
    $key_3e6c = { 6a 04 [2] 1e 1c [2] 59 1e [2] 1e 0f [2] 50 03 [2] 5c 09 [2] 4b 02 [2] 50 4c [2] 6d }

  condition:
    any of them
}