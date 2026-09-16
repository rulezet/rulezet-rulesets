rule TTP_XOR_QUAD_CurrentVersionRun_e3ec {
  strings:
    $key_e3ec = { b0 83 [2] 94 8d [2] bf a1 [2] 91 83 [2] 85 98 [2] 8a 82 [2] 94 9f [2] 96 9e [2] 8d 98 [2] 91 9f [2] 8d b0 }

  condition:
    any of them
}