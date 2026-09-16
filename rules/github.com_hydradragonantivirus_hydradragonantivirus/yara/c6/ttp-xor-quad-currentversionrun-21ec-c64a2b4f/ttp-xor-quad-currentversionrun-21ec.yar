rule TTP_XOR_QUAD_CurrentVersionRun_21ec {
  strings:
    $key_21ec = { 72 83 [2] 56 8d [2] 7d a1 [2] 53 83 [2] 47 98 [2] 48 82 [2] 56 9f [2] 54 9e [2] 4f 98 [2] 53 9f [2] 4f b0 }

  condition:
    any of them
}