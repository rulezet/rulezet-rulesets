rule TTP_XOR_QUAD_CurrentVersionRun_face {
  strings:
    $key_face = { a9 a1 [2] 8d af [2] a6 83 [2] 88 a1 [2] 9c ba [2] 93 a0 [2] 8d bd [2] 8f bc [2] 94 ba [2] 88 bd [2] 94 92 }

  condition:
    any of them
}