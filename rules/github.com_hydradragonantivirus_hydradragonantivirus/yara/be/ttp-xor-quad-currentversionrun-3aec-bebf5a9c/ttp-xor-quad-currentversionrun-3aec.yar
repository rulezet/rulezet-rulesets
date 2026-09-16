rule TTP_XOR_QUAD_CurrentVersionRun_3aec {
  strings:
    $key_3aec = { 69 83 [2] 4d 8d [2] 66 a1 [2] 48 83 [2] 5c 98 [2] 53 82 [2] 4d 9f [2] 4f 9e [2] 54 98 [2] 48 9f [2] 54 b0 }

  condition:
    any of them
}