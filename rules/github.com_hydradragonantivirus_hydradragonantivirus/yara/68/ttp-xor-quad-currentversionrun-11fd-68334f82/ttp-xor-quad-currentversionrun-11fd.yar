rule TTP_XOR_QUAD_CurrentVersionRun_11fd {
  strings:
    $key_11fd = { 42 92 [2] 66 9c [2] 4d b0 [2] 63 92 [2] 77 89 [2] 78 93 [2] 66 8e [2] 64 8f [2] 7f 89 [2] 63 8e [2] 7f a1 }

  condition:
    any of them
}