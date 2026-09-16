rule TTP_XOR_QUAD_CurrentVersionRun_b9ba {
  strings:
    $key_b9ba = { ea d5 [2] ce db [2] e5 f7 [2] cb d5 [2] df ce [2] d0 d4 [2] ce c9 [2] cc c8 [2] d7 ce [2] cb c9 [2] d7 e6 }

  condition:
    any of them
}