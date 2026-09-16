rule TTP_XOR_QUAD_CurrentVersionRun_a9ba {
  strings:
    $key_a9ba = { fa d5 [2] de db [2] f5 f7 [2] db d5 [2] cf ce [2] c0 d4 [2] de c9 [2] dc c8 [2] c7 ce [2] db c9 [2] c7 e6 }

  condition:
    any of them
}