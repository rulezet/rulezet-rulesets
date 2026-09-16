rule TTP_XOR_QUAD_CurrentVersionRun_bed1 {
  strings:
    $key_bed1 = { ed be [2] c9 b0 [2] e2 9c [2] cc be [2] d8 a5 [2] d7 bf [2] c9 a2 [2] cb a3 [2] d0 a5 [2] cc a2 [2] d0 8d }

  condition:
    any of them
}