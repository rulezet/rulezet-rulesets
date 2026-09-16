rule TTP_XOR_QUAD_CurrentVersionRun_1ba3 {
  strings:
    $key_1ba3 = { 48 cc [2] 6c c2 [2] 47 ee [2] 69 cc [2] 7d d7 [2] 72 cd [2] 6c d0 [2] 6e d1 [2] 75 d7 [2] 69 d0 [2] 75 ff }

  condition:
    any of them
}