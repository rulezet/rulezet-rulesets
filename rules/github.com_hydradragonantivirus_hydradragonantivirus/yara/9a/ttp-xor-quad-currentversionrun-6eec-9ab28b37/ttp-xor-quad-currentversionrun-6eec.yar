rule TTP_XOR_QUAD_CurrentVersionRun_6eec {
  strings:
    $key_6eec = { 3d 83 [2] 19 8d [2] 32 a1 [2] 1c 83 [2] 08 98 [2] 07 82 [2] 19 9f [2] 1b 9e [2] 00 98 [2] 1c 9f [2] 00 b0 }

  condition:
    any of them
}