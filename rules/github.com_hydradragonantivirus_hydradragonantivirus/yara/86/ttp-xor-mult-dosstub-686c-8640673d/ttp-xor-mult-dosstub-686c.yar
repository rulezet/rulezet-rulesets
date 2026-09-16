rule TTP_XOR_MULT_DOSStub_686c {
  strings:
    $key_686c = { 3c 04 [2] 48 1c [2] 0f 1e [2] 48 0f [2] 06 03 [2] 0a 09 [2] 1d 02 [2] 06 4c [2] 3b }

  condition:
    any of them
}