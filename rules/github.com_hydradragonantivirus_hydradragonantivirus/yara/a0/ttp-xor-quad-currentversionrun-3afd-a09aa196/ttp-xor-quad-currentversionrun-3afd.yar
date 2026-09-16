rule TTP_XOR_QUAD_CurrentVersionRun_3afd {
  strings:
    $key_3afd = { 69 92 [2] 4d 9c [2] 66 b0 [2] 48 92 [2] 5c 89 [2] 53 93 [2] 4d 8e [2] 4f 8f [2] 54 89 [2] 48 8e [2] 54 a1 }

  condition:
    any of them
}