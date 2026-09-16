rule TTP_XOR_QUAD_CurrentVersionRun_ea3d {
  strings:
    $key_ea3d = { b9 52 [2] 9d 5c [2] b6 70 [2] 98 52 [2] 8c 49 [2] 83 53 [2] 9d 4e [2] 9f 4f [2] 84 49 [2] 98 4e [2] 84 61 }

  condition:
    any of them
}