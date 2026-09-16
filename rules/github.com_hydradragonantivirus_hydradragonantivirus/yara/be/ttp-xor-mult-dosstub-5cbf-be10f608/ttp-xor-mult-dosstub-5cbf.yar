rule TTP_XOR_MULT_DOSStub_5cbf {
  strings:
    $key_5cbf = { 08 d7 [2] 7c cf [2] 3b cd [2] 7c dc [2] 32 d0 [2] 3e da [2] 29 d1 [2] 32 9f [2] 0f }

  condition:
    any of them
}