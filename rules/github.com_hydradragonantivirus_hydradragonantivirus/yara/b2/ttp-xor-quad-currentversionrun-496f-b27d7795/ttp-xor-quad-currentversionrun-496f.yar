rule TTP_XOR_QUAD_CurrentVersionRun_496f {
  strings:
    $key_496f = { 1a 00 [2] 3e 0e [2] 15 22 [2] 3b 00 [2] 2f 1b [2] 20 01 [2] 3e 1c [2] 3c 1d [2] 27 1b [2] 3b 1c [2] 27 33 }

  condition:
    any of them
}