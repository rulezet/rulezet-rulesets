rule TTP_XOR_MULT_DOSStub_101b {
  strings:
    $key_101b = { 44 73 [2] 30 6b [2] 77 69 [2] 30 78 [2] 7e 74 [2] 72 7e [2] 65 75 [2] 7e 3b [2] 43 }

  condition:
    any of them
}