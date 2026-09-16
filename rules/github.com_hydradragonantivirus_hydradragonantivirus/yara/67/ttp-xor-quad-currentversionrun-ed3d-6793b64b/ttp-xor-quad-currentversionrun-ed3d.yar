rule TTP_XOR_QUAD_CurrentVersionRun_ed3d {
  strings:
    $key_ed3d = { be 52 [2] 9a 5c [2] b1 70 [2] 9f 52 [2] 8b 49 [2] 84 53 [2] 9a 4e [2] 98 4f [2] 83 49 [2] 9f 4e [2] 83 61 }

  condition:
    any of them
}