rule TTP_XOR_QUAD_CurrentVersionRun_beb6 {
  strings:
    $key_beb6 = { ed d9 [2] c9 d7 [2] e2 fb [2] cc d9 [2] d8 c2 [2] d7 d8 [2] c9 c5 [2] cb c4 [2] d0 c2 [2] cc c5 [2] d0 ea }

  condition:
    any of them
}