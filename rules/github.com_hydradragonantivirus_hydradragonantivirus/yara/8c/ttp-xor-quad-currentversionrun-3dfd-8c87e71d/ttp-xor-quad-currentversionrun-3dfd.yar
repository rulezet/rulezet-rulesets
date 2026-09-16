rule TTP_XOR_QUAD_CurrentVersionRun_3dfd {
  strings:
    $key_3dfd = { 6e 92 [2] 4a 9c [2] 61 b0 [2] 4f 92 [2] 5b 89 [2] 54 93 [2] 4a 8e [2] 48 8f [2] 53 89 [2] 4f 8e [2] 53 a1 }

  condition:
    any of them
}