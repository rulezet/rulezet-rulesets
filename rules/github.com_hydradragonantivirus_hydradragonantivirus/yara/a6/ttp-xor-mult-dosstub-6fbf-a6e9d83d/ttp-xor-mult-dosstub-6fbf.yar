rule TTP_XOR_MULT_DOSStub_6fbf {
  strings:
    $key_6fbf = { 3b d7 [2] 4f cf [2] 08 cd [2] 4f dc [2] 01 d0 [2] 0d da [2] 1a d1 [2] 01 9f [2] 3c }

  condition:
    any of them
}