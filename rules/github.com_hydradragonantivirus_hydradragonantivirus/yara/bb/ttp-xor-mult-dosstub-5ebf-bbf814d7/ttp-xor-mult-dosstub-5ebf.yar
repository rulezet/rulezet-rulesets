rule TTP_XOR_MULT_DOSStub_5ebf {
  strings:
    $key_5ebf = { 0a d7 [2] 7e cf [2] 39 cd [2] 7e dc [2] 30 d0 [2] 3c da [2] 2b d1 [2] 30 9f [2] 0d }

  condition:
    any of them
}