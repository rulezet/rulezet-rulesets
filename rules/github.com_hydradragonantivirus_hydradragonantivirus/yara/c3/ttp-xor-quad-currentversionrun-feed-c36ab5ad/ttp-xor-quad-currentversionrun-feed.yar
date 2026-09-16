rule TTP_XOR_QUAD_CurrentVersionRun_feed {
  strings:
    $key_feed = { ad 82 [2] 89 8c [2] a2 a0 [2] 8c 82 [2] 98 99 [2] 97 83 [2] 89 9e [2] 8b 9f [2] 90 99 [2] 8c 9e [2] 90 b1 }

  condition:
    any of them
}