rule TTP_XOR_QUAD_CurrentVersionRun_3d21 {
  strings:
    $key_3d21 = { 6e 4e [2] 4a 40 [2] 61 6c [2] 4f 4e [2] 5b 55 [2] 54 4f [2] 4a 52 [2] 48 53 [2] 53 55 [2] 4f 52 [2] 53 7d }

  condition:
    any of them
}