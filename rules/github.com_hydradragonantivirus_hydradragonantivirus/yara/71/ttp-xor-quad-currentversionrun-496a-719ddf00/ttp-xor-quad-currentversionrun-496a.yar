rule TTP_XOR_QUAD_CurrentVersionRun_496a {
  strings:
    $key_496a = { 1a 05 [2] 3e 0b [2] 15 27 [2] 3b 05 [2] 2f 1e [2] 20 04 [2] 3e 19 [2] 3c 18 [2] 27 1e [2] 3b 19 [2] 27 36 }

  condition:
    any of them
}