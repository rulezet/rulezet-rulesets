rule TTP_XOR_MULT_DOSStub_5fbf {
  strings:
    $key_5fbf = { 0b d7 [2] 7f cf [2] 38 cd [2] 7f dc [2] 31 d0 [2] 3d da [2] 2a d1 [2] 31 9f [2] 0c }

  condition:
    any of them
}