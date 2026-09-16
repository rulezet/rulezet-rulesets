rule TTP_XOR_MULT_DOSStub_726c {
  strings:
    $key_726c = { 26 04 [2] 52 1c [2] 15 1e [2] 52 0f [2] 1c 03 [2] 10 09 [2] 07 02 [2] 1c 4c [2] 21 }

  condition:
    any of them
}