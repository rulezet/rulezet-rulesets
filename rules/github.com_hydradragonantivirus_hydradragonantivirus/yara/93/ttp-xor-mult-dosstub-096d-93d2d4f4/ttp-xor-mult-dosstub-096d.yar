rule TTP_XOR_MULT_DOSStub_096d {
  strings:
    $key_096d = { 5d 05 [2] 29 1d [2] 6e 1f [2] 29 0e [2] 67 02 [2] 6b 08 [2] 7c 03 [2] 67 4d [2] 5a }

  condition:
    any of them
}