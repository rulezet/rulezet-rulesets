rule TTP_XOR_QUAD_CurrentVersionRun_483d {
  strings:
    $key_483d = { 1b 52 [2] 3f 5c [2] 14 70 [2] 3a 52 [2] 2e 49 [2] 21 53 [2] 3f 4e [2] 3d 4f [2] 26 49 [2] 3a 4e [2] 26 61 }

  condition:
    any of them
}