rule TTP_XOR_QUAD_CurrentVersionRun_eda3 {
  strings:
    $key_eda3 = { be cc [2] 9a c2 [2] b1 ee [2] 9f cc [2] 8b d7 [2] 84 cd [2] 9a d0 [2] 98 d1 [2] 83 d7 [2] 9f d0 [2] 83 ff }

  condition:
    any of them
}