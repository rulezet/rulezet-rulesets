rule TTP_XOR_MULT_DOSStub_1cbf {
  strings:
    $key_1cbf = { 48 d7 [2] 3c cf [2] 7b cd [2] 3c dc [2] 72 d0 [2] 7e da [2] 69 d1 [2] 72 9f [2] 4f }

  condition:
    any of them
}