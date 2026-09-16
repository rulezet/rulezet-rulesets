rule TTP_XOR_QUAD_CurrentVersionRun_fb3d {
  strings:
    $key_fb3d = { a8 52 [2] 8c 5c [2] a7 70 [2] 89 52 [2] 9d 49 [2] 92 53 [2] 8c 4e [2] 8e 4f [2] 95 49 [2] 89 4e [2] 95 61 }

  condition:
    any of them
}