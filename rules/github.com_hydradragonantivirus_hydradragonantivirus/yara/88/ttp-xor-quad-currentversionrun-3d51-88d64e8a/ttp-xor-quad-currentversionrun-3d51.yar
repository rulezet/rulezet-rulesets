rule TTP_XOR_QUAD_CurrentVersionRun_3d51 {
  strings:
    $key_3d51 = { 6e 3e [2] 4a 30 [2] 61 1c [2] 4f 3e [2] 5b 25 [2] 54 3f [2] 4a 22 [2] 48 23 [2] 53 25 [2] 4f 22 [2] 53 0d }

  condition:
    any of them
}