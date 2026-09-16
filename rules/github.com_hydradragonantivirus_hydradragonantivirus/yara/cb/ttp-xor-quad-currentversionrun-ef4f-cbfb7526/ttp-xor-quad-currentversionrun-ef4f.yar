rule TTP_XOR_QUAD_CurrentVersionRun_ef4f {
  strings:
    $key_ef4f = { bc 20 [2] 98 2e [2] b3 02 [2] 9d 20 [2] 89 3b [2] 86 21 [2] 98 3c [2] 9a 3d [2] 81 3b [2] 9d 3c [2] 81 13 }

  condition:
    any of them
}