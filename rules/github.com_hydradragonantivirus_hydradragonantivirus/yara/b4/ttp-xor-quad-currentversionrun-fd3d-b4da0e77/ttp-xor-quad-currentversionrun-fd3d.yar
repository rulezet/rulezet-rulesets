rule TTP_XOR_QUAD_CurrentVersionRun_fd3d {
  strings:
    $key_fd3d = { ae 52 [2] 8a 5c [2] a1 70 [2] 8f 52 [2] 9b 49 [2] 94 53 [2] 8a 4e [2] 88 4f [2] 93 49 [2] 8f 4e [2] 93 61 }

  condition:
    any of them
}