rule TTP_XOR_QUAD_CurrentVersionRun_48f0 {
  strings:
    $key_48f0 = { 1b 9f [2] 3f 91 [2] 14 bd [2] 3a 9f [2] 2e 84 [2] 21 9e [2] 3f 83 [2] 3d 82 [2] 26 84 [2] 3a 83 [2] 26 ac }

  condition:
    any of them
}