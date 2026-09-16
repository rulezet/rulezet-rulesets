rule TTP_XOR_MULT_DOSStub_4fbf {
  strings:
    $key_4fbf = { 1b d7 [2] 6f cf [2] 28 cd [2] 6f dc [2] 21 d0 [2] 2d da [2] 3a d1 [2] 21 9f [2] 1c }

  condition:
    any of them
}