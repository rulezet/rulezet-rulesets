rule TTP_XOR_MULT_DOSStub_696b {
  strings:
    $key_696b = { 3d 03 [2] 49 1b [2] 0e 19 [2] 49 08 [2] 07 04 [2] 0b 0e [2] 1c 05 [2] 07 4b [2] 3a }

  condition:
    any of them
}