rule TTP_XOR_QUAD_CurrentVersionRun_cfd2 {
  strings:
    $key_cfd2 = { 9c bd [2] b8 b3 [2] 93 9f [2] bd bd [2] a9 a6 [2] a6 bc [2] b8 a1 [2] ba a0 [2] a1 a6 [2] bd a1 [2] a1 8e }

  condition:
    any of them
}