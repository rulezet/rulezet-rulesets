rule TTP_XOR_QUAD_CurrentVersionRun_a5a2 {
  strings:
    $key_a5a2 = { f6 cd [2] d2 c3 [2] f9 ef [2] d7 cd [2] c3 d6 [2] cc cc [2] d2 d1 [2] d0 d0 [2] cb d6 [2] d7 d1 [2] cb fe }

  condition:
    any of them
}