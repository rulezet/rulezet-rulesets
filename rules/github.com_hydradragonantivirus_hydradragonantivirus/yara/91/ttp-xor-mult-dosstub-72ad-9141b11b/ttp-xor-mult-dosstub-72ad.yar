rule TTP_XOR_MULT_DOSStub_72ad {
  strings:
    $key_72ad = { 26 c5 [2] 52 dd [2] 15 df [2] 52 ce [2] 1c c2 [2] 10 c8 [2] 07 c3 [2] 1c 8d [2] 21 }

  condition:
    any of them
}