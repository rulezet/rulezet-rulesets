rule TTP_XOR_QUAD_CurrentVersionRun_496c {
  strings:
    $key_496c = { 1a 03 [2] 3e 0d [2] 15 21 [2] 3b 03 [2] 2f 18 [2] 20 02 [2] 3e 1f [2] 3c 1e [2] 27 18 [2] 3b 1f [2] 27 30 }

  condition:
    any of them
}