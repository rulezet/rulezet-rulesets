rule TTP_XOR_MULT_DOSStub_3ebf {
  strings:
    $key_3ebf = { 6a d7 [2] 1e cf [2] 59 cd [2] 1e dc [2] 50 d0 [2] 5c da [2] 4b d1 [2] 50 9f [2] 6d }

  condition:
    any of them
}