rule TTP_XOR_MULT_DOSStub_690b {
  strings:
    $key_690b = { 3d 63 [2] 49 7b [2] 0e 79 [2] 49 68 [2] 07 64 [2] 0b 6e [2] 1c 65 [2] 07 2b [2] 3a }

  condition:
    any of them
}