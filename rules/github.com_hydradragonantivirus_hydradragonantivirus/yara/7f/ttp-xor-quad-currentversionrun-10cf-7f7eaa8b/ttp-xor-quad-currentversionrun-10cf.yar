rule TTP_XOR_QUAD_CurrentVersionRun_10cf {
  strings:
    $key_10cf = { 43 a0 [2] 67 ae [2] 4c 82 [2] 62 a0 [2] 76 bb [2] 79 a1 [2] 67 bc [2] 65 bd [2] 7e bb [2] 62 bc [2] 7e 93 }

  condition:
    any of them
}