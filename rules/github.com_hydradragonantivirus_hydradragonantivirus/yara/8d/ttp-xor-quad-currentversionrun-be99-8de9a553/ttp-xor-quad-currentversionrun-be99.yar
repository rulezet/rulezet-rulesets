rule TTP_XOR_QUAD_CurrentVersionRun_be99 {
  strings:
    $key_be99 = { ed f6 [2] c9 f8 [2] e2 d4 [2] cc f6 [2] d8 ed [2] d7 f7 [2] c9 ea [2] cb eb [2] d0 ed [2] cc ea [2] d0 c5 }

  condition:
    any of them
}