rule TTP_XOR_QUAD_CurrentVersionRun_eed2 {
  strings:
    $key_eed2 = { bd bd [2] 99 b3 [2] b2 9f [2] 9c bd [2] 88 a6 [2] 87 bc [2] 99 a1 [2] 9b a0 [2] 80 a6 [2] 9c a1 [2] 80 8e }

  condition:
    any of them
}