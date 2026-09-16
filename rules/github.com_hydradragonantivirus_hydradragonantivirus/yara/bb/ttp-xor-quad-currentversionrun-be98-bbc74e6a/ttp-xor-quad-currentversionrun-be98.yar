rule TTP_XOR_QUAD_CurrentVersionRun_be98 {
  strings:
    $key_be98 = { ed f7 [2] c9 f9 [2] e2 d5 [2] cc f7 [2] d8 ec [2] d7 f6 [2] c9 eb [2] cb ea [2] d0 ec [2] cc eb [2] d0 c4 }

  condition:
    any of them
}