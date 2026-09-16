rule TTP_XOR_QUAD_CurrentVersionRun_beb1 {
  strings:
    $key_beb1 = { ed de [2] c9 d0 [2] e2 fc [2] cc de [2] d8 c5 [2] d7 df [2] c9 c2 [2] cb c3 [2] d0 c5 [2] cc c2 [2] d0 ed }

  condition:
    any of them
}