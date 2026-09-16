rule TTP_XOR_QUAD_CurrentVersionRun_becf {
  strings:
    $key_becf = { ed a0 [2] c9 ae [2] e2 82 [2] cc a0 [2] d8 bb [2] d7 a1 [2] c9 bc [2] cb bd [2] d0 bb [2] cc bc [2] d0 93 }

  condition:
    any of them
}