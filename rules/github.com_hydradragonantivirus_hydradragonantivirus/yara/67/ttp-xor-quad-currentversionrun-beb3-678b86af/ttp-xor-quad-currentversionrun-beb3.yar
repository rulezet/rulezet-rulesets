rule TTP_XOR_QUAD_CurrentVersionRun_beb3 {
  strings:
    $key_beb3 = { ed dc [2] c9 d2 [2] e2 fe [2] cc dc [2] d8 c7 [2] d7 dd [2] c9 c0 [2] cb c1 [2] d0 c7 [2] cc c0 [2] d0 ef }

  condition:
    any of them
}