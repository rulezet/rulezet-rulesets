rule TTP_XOR_QUAD_CurrentVersionRun_bf87 {
  strings:
    $key_bf87 = { ec e8 [2] c8 e6 [2] e3 ca [2] cd e8 [2] d9 f3 [2] d6 e9 [2] c8 f4 [2] ca f5 [2] d1 f3 [2] cd f4 [2] d1 db }

  condition:
    any of them
}