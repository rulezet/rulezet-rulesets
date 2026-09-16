rule TTP_XOR_QUAD_CurrentVersionRun_f9c8 {
  strings:
    $key_f9c8 = { aa a7 [2] 8e a9 [2] a5 85 [2] 8b a7 [2] 9f bc [2] 90 a6 [2] 8e bb [2] 8c ba [2] 97 bc [2] 8b bb [2] 97 94 }

  condition:
    any of them
}