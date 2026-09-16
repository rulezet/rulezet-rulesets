rule TTP_XOR_QUAD_CurrentVersionRun_eda6 {
  strings:
    $key_eda6 = { be c9 [2] 9a c7 [2] b1 eb [2] 9f c9 [2] 8b d2 [2] 84 c8 [2] 9a d5 [2] 98 d4 [2] 83 d2 [2] 9f d5 [2] 83 fa }

  condition:
    any of them
}