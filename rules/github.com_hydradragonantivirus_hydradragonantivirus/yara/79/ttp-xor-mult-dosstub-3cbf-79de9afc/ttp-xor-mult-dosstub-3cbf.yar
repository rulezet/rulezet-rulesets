rule TTP_XOR_MULT_DOSStub_3cbf {
  strings:
    $key_3cbf = { 68 d7 [2] 1c cf [2] 5b cd [2] 1c dc [2] 52 d0 [2] 5e da [2] 49 d1 [2] 52 9f [2] 6f }

  condition:
    any of them
}