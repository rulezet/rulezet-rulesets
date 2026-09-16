rule TTP_XOR_QUAD_CurrentVersionRun_3da3 {
  strings:
    $key_3da3 = { 6e cc [2] 4a c2 [2] 61 ee [2] 4f cc [2] 5b d7 [2] 54 cd [2] 4a d0 [2] 48 d1 [2] 53 d7 [2] 4f d0 [2] 53 ff }

  condition:
    any of them
}