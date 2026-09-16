rule TTP_XOR_MULT_DOSStub_106c {
  strings:
    $key_106c = { 44 04 [2] 30 1c [2] 77 1e [2] 30 0f [2] 7e 03 [2] 72 09 [2] 65 02 [2] 7e 4c [2] 43 }

  condition:
    any of them
}