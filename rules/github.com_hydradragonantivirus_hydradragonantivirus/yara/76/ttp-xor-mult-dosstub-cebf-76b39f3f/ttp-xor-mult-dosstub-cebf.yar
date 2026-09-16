rule TTP_XOR_MULT_DOSStub_cebf {
  strings:
    $key_cebf = { 9a d7 [2] ee cf [2] a9 cd [2] ee dc [2] a0 d0 [2] ac da [2] bb d1 [2] a0 9f [2] 9d }

  condition:
    any of them
}