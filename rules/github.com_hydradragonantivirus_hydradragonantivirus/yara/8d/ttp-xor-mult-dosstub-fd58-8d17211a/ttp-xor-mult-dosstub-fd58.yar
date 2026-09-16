rule TTP_XOR_MULT_DOSStub_fd58 {
  strings:
    $key_fd58 = { a9 30 [2] dd 28 [2] 9a 2a [2] dd 3b [2] 93 37 [2] 9f 3d [2] 88 36 [2] 93 78 [2] ae }

  condition:
    any of them
}