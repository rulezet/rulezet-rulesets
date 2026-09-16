rule TTP_XOR_MULT_DOSStub_9f71 {
  strings:
    $key_9f71 = { cb 19 [2] bf 01 [2] f8 03 [2] bf 12 [2] f1 1e [2] fd 14 [2] ea 1f [2] f1 51 [2] cc }

  condition:
    any of them
}