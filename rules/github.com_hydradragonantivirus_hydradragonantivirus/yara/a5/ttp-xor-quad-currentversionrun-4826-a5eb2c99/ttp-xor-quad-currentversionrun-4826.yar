rule TTP_XOR_QUAD_CurrentVersionRun_4826 {
  strings:
    $key_4826 = { 1b 49 [2] 3f 47 [2] 14 6b [2] 3a 49 [2] 2e 52 [2] 21 48 [2] 3f 55 [2] 3d 54 [2] 26 52 [2] 3a 55 [2] 26 7a }

  condition:
    any of them
}